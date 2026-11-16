using System.Net;
using System.Net.Sockets;

namespace ProxyBridge.Core;

/// <summary>
/// Проверка доступности прокси: не просто «порт открыт», а живое SOCKS5-рукопожатие.
/// Порт может слушать совсем другой сервис — тогда клиент получит непонятную ошибку.
/// Результат — человекочитаемый, без «хост неизвестен».
/// </summary>
public static class ProxyProbe
{
    /// <summary>
    /// Проверяет, что по адресу отвечает наш прокси. Возвращает (ok, сообщение).
    /// </summary>
    public static async Task<(bool Ok, string Message)> CheckAsync(string? host, int port, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(host))
            return (false, "Не указан адрес телефона.");

        var trimmed = host.Trim();
        if (!IPAddress.TryParse(trimmed, out var ip))
            return (false, $"Адрес «{trimmed}» должен быть числом, например 192.168.43.1.");

        if (ip.Equals(IPAddress.Any))
            return (false, "Адрес 0.0.0.0 не подходит — укажите IP телефона в точке доступа.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));

        try
        {
            using var client = new TcpClient { NoDelay = true };
            await client.ConnectAsync(ip, port, timeout.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();

            // SOCKS5 greeting: ver=5, один метод, no-auth
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);

            var buffer = new byte[2];
            var read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read >= 2 && buffer[0] == 0x05)
                return (true, $"Прокси на {ip}:{port} отвечает (SOCKS5)");

            return (false, $"По адресу {ip}:{port} отвечает не прокси — проверьте порт.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (false, $"Нет ответа от {ip}:{port} — телефон не в этой сети или прокси на нём не запущен.");
        }
        catch (SocketException ex)
        {
            return (false, Describe(ex, ip, port));
        }
        catch (Exception ex)
        {
            return (false, $"Не удалось проверить {ip}:{port}: {ex.Message}");
        }
    }

    /// <summary>
    /// Сквозная проверка канала: TCP → SOCKS5-рукопожатие → CONNECT к внешнему узлу.
    /// Только она доказывает, что через прокси действительно пойдёт трафик, поэтому включать
    /// системный прокси на ноутбуке можно лишь после успеха этой проверки.
    /// </summary>
    public static async Task<(bool Ok, string Message)> CheckEndToEndAsync(
        string? host, int port, CancellationToken ct = default, IPAddress? target = null, int targetPort = 443)
    {
        if (string.IsNullOrWhiteSpace(host))
            return (false, "Не указан адрес телефона.");

        var trimmed = host.Trim();
        if (!IPAddress.TryParse(trimmed, out var ip))
            return (false, $"Адрес «{trimmed}» должен быть числом, например 192.168.43.1.");

        if (ip.Equals(IPAddress.Any))
            return (false, "Адрес 0.0.0.0 не подходит — укажите IP телефона в точке доступа.");

        // Цель проверки — заведомо живой внешний адрес, без DNS:
        // если и он не открывается, канал не работает.
        var probeHost = target ?? IPAddress.Parse("1.1.1.1");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(4));

        try
        {
            using var client = new TcpClient { NoDelay = true };
            await client.ConnectAsync(ip, port, timeout.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();

            // 1. SOCKS5: приветствие без авторизации
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);

            var reply = new byte[2];
            if (await stream.ReadAsync(reply, timeout.Token).ConfigureAwait(false) < 2 || reply[0] != 0x05)
                return (false, $"По адресу {ip}:{port} отвечает не прокси — проверьте порт.");

            if (reply[1] != 0x00)
                return (false, $"Прокси на {ip} требует авторизацию — она в приложении не настроена.");

            // 2. Запрос на соединение с внешним узлом (только IPv4-цель, без имени)
            var address = probeHost.GetAddressBytes();
            if (address.Length != 4)
                return (false, "Внутренняя ошибка проверки: цель должна быть IPv4.");

            var request = new byte[10];
            request[0] = 0x05;                        // версия
            request[1] = 0x01;                        // CONNECT
            request[2] = 0x00;                        // зарезервировано
            request[3] = 0x01;                        // ATYP = IPv4
            address.CopyTo(request, 4);
            request[8] = (byte)(targetPort >> 8);
            request[9] = (byte)(targetPort & 0xFF);

            await stream.WriteAsync(request, timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);

            var answer = new byte[4];
            if (await stream.ReadAsync(answer, timeout.Token).ConfigureAwait(false) < 4 || answer[0] != 0x05)
                return (false, $"Прокси {ip}:{port} не ответил на запрос соединения.");

            if (answer[1] == 0x00)
                return (true, $"Канал работает: {ip}:{port} → интернет");

            return (false, answer[1] switch
            {
                0x02 => "Прокси телефона запрещает такие соединения.",
                0x03 => "Сеть недоступна: у телефона нет интернета.",
                0x04 => "Хост недоступен: у телефона нет интернета.",
                0x05 => "Соединение отклонено — у телефона нет выхода в сеть.",
                0x06 => "Истекло время ожидания — у телефона нет выхода в сеть.",
                0x07 => "Прокси телефона не поддерживает этот тип запроса.",
                0x08 => "Прокси телефона не понимает адрес назначения.",
                _ => $"Прокси телефона вернул ошибку 0x{answer[1]:X2}.",
            });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (false, $"Нет ответа от {ip}:{port} — телефон не в этой сети или прокси на нём не запущен.");
        }
        catch (SocketException ex)
        {
            return (false, Describe(ex, ip, port));
        }
        catch (Exception ex)
        {
            return (false, $"Не удалось проверить {ip}:{port}: {ex.Message}");
        }
    }

    /// <summary>Человекочитаемое объяснение сетевой ошибки.</summary>
    public static string Describe(SocketException ex, IPAddress ip, int port)
    {
        var where = $"{ip}:{port}";

        return ex.SocketErrorCode switch
        {
            SocketError.HostNotFound =>
                $"Хост {where} не найден — проверьте IP-адрес телефона (в точке доступа он обычно 192.168.43.1).",
            SocketError.TryAgain =>
                $"Хост {where} не отвечает — телефон не в этой сети.",
            SocketError.ConnectionRefused =>
                $"Соединение к {where} отклонено — прокси на телефоне не запущен или указан неверный порт.",
            SocketError.NetworkUnreachable =>
                $"Сеть до {where} недоступна — вы не подключены к точке доступа телефона.",
            SocketError.TimedOut =>
                $"Превышен таймаут при обращении к {where}.",
            _ =>
                $"Ошибка подключения к {where}: {ex.SocketErrorCode} ({ex.Message}).",
        };
    }
}
