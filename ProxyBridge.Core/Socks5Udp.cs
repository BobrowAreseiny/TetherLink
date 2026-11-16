using System.Net;
using System.Net.Sockets;

namespace ProxyBridge.Core;

/// <summary>
/// SOCKS5 UDP ASSOCIATE (RFC 1928, раздел 7).
/// Нужен, чтобы через прокси шёл не только TCP: DNS, QUIC/HTTP3, WebRTC, игровые протоколы.
///
/// Схема: клиент шлёт датаграммы на UDP-порт, который сервер сообщил в ответе на ASSOCIATE.
/// Каждая датаграмма обёрнута в SOCKS5-заголовок (RSV, FRAG, ATYP, ADDR, PORT, DATA).
///
/// Важно: UDP-порт клиента НЕ совпадает с портом его TCP-соединения, поэтому
/// «свой/чужой» определяется по IP-адресу и по разбору заголовка, а отвечаем всегда
/// на фактический источник клиентской датаграммы.
/// </summary>
internal static class Socks5Udp
{
    /// <summary>
    /// Обслуживает UDP-сеанс: читает датаграммы клиента, отправляет полезную нагрузку
    /// адресату через отдельный сокет и возвращает ответы клиенту.
    /// </summary>
    public static async Task RelayAsync(UdpClient relay, IPAddress clientAddress, CancellationToken ct, Action<string>? log)
    {
        // Исходящие сокеты: по одному на уникальный адрес назначения.
        // Ответы серверов приходят на них, а не на relay-сокет, поэтому «свой/чужой»
        // на relay-сокете не путается.
        var upstreamSockets = new Dictionary<(string Host, int Port), UdpClient>();

        // Фактический UDP-эндпоинт клиента — узнаём из его первой датаграммы.
        IPEndPoint? clientEndpoint = null;

        log?.Invoke($"UDP relay старт: ждём датаграммы от {clientAddress} на {(relay.Client.LocalEndPoint as IPEndPoint)?.Port}");

        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult received;
                try
                {
                    received = await relay.ReceiveAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    log?.Invoke("UDP relay: отменён");
                    break;
                }
                catch (ObjectDisposedException) { break; }
                catch (SocketException ex)
                {
                    log?.Invoke($"UDP relay сокет: {ex.SocketErrorCode} {ex.Message}");
                    break;
                }

                // Принимаем только пакеты с адреса клиента (RFC 1928, раздел 7).
                if (!received.RemoteEndPoint.Address.Equals(clientAddress))
                {
                    log?.Invoke($"UDP: пакет с чужого адреса {received.RemoteEndPoint} — пропущен");
                    continue;
                }

                var request = ParseRequest(received.Buffer);
                if (request is null)
                {
                    log?.Invoke("UDP: некорректный заголовок датаграммы, пропущен");
                    continue;
                }

                // Запоминаем настоящий UDP-адрес клиента: отвечать нужно именно на него.
                clientEndpoint = received.RemoteEndPoint;

                var (host, port, payload) = request.Value;

                // ЖЁСТКАЯ ЗАЩИТА: UDP — такой же канал наружу, и его тоже нельзя
                // пускать к десктопным целям.
                if (CarrierStealthFilter.ShouldBlockHost(host))
                {
                    log?.Invoke($"Заблокирован UDP-канал к телеметрии: {host}");
                    continue;
                }

                var key = (host, port);

                if (!upstreamSockets.TryGetValue(key, out var upstream))
                {
                    // Сокет обязательно привязываем к свободному порту: без Bind
                    // ReceiveAsync бросает «You must call the Bind method», и приём
                    // ответов умирает сразу — клиент не получает ничего.
                    upstream = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                    upstreamSockets[key] = upstream;

                    // Маскировка: TTL = 64 как у Android, иначе оператор увидит Windows
                    try { upstream.Client.Ttl = 64; } catch { /* не критично */ }

                    _ = PumpUpstreamAsync(upstream, relay, () => clientEndpoint, ct, log);
                    log?.Invoke($"UDP: новый канал к {host}:{port}");
                }

                try
                {
                    await upstream.SendAsync(payload, payload.Length, host, port).ConfigureAwait(false);
                }
                catch (SocketException ex)
                {
                    log?.Invoke($"UDP {host}:{port}: {ex.SocketErrorCode} {ex.Message}");
                }
            }
        }
        finally
        {
            foreach (var socket in upstreamSockets.Values)
                socket.Dispose();
        }
    }

    /// <summary>Ответы от сервера: заворачиваем в SOCKS5-заголовок и отдаём клиенту.</summary>
    private static async Task PumpUpstreamAsync(UdpClient upstream, UdpClient relay, Func<IPEndPoint?> client, CancellationToken ct, Action<string>? log)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var received = await upstream.ReceiveAsync(ct).ConfigureAwait(false);

                var target = client();
                if (target is null)
                {
                    log?.Invoke("UDP: адрес клиента ещё неизвестен, ответ отброшен");
                    continue;
                }

                var reply = BuildReply(received.Buffer, received.RemoteEndPoint);
                if (reply is null) continue;

                await SendAsync(relay, reply, target, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException ex)
        {
            log?.Invoke($"UDP приём ответа: {ex.SocketErrorCode} {ex.Message}");
        }
        catch (Exception ex)
        {
            log?.Invoke($"UDP приём ответа: {ex.Message}");
        }
    }

    private static async Task SendAsync(UdpClient socket, byte[] data, IPEndPoint target, CancellationToken ct)
    {
        try
        {
            await socket.SendAsync(data, data.Length, target).WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException ex)
        {
            // ICMP port unreachable от предыдущей датаграммы — нормальный шум UDP
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] UDP send: {ex.SocketErrorCode}");
        }
    }

    /// <summary>Разбирает SOCKS5 UDP-запрос: возвращает (host, port, payload).</summary>
    internal static (string Host, int Port, byte[] Payload)? ParseRequest(byte[] datagram)
    {
        if (datagram.Length < 4) return null;

        // RSV и FRAG: фрагментацию не поддерживаем (FRAG должен быть 0)
        if (datagram[2] != 0x00) return null;
        if (datagram[3] == 0x00) return null; // ATYP не может быть 0

        var atyp = datagram[3];
        int offset;
        string host;

        switch (atyp)
        {
            case 0x01: // IPv4
                if (datagram.Length < 10) return null;
                host = new IPAddress(datagram.AsSpan(4, 4)).ToString();
                offset = 8;
                break;
            case 0x03: // домен
                {
                    var len = datagram[4];
                    if (len == 0) return null;
                    if (datagram.Length < 5 + len + 2) return null;
                    host = System.Text.Encoding.ASCII.GetString(datagram, 5, len);
                    offset = 5 + len;
                    break;
                }
            case 0x04: // IPv6
                if (datagram.Length < 22) return null;
                host = new IPAddress(datagram.AsSpan(4, 16)).ToString();
                offset = 20;
                break;
            default:
                return null;
        }

        var port = (datagram[offset] << 8) | datagram[offset + 1];
        var payloadOffset = offset + 2;
        if (payloadOffset > datagram.Length) return null;

        var payload = new byte[datagram.Length - payloadOffset];
        Buffer.BlockCopy(datagram, payloadOffset, payload, 0, payload.Length);
        return (host, port, payload);
    }

    /// <summary>Заворачивает ответ сервера обратно в SOCKS5-UDP-формат для клиента.</summary>
    private static byte[]? BuildReply(byte[] payload, IPEndPoint source)
    {
        var isV4 = source.Address.AddressFamily == AddressFamily.InterNetwork;
        var addressLength = isV4 ? 4 : 16;

        var result = new byte[4 + addressLength + 2 + payload.Length];
        result[0] = 0x00;
        result[1] = 0x00;
        result[2] = 0x00; // FRAG = 0
        result[3] = (byte)(isV4 ? 0x01 : 0x04);

        var bytes = source.Address.GetAddressBytes();
        Buffer.BlockCopy(bytes, 0, result, 4, addressLength);

        var portOffset = 4 + addressLength;
        result[portOffset] = (byte)(source.Port >> 8);
        result[portOffset + 1] = (byte)(source.Port & 0xFF);

        Buffer.BlockCopy(payload, 0, result, portOffset + 2, payload.Length);
        return result;
    }
}
