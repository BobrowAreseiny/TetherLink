using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProxyBridge.Windows.Services;

/// <summary>
/// Ищет телефон без подсказок пользователя: в точке доступа телефон и есть шлюз по умолчанию
/// для Wi-Fi-адаптера. Это надёжнее догадок про 192.168.43.1 — Samsung, например, раздаёт
/// случайную подсеть вида 10.240.x.x/24, и угадать её невозможно.
/// </summary>
internal static class GatewayProbe
{
    private static readonly string[] TunnelHints =
    [
        "amnezia", "wireguard", "openvpn", "wintun", "tap-", "tap0", "vpn", "tunnel",
        "zerotier", "tailscale", "hamachi", "radmin",
    ];

    /// <summary>IPv4-адрес шлюза Wi-Fi (он же телефон в точке доступа) или null.</summary>
    public static string? DetectPhoneAddress()
    {
        var candidates = new List<(NetworkInterfaceType Type, string Name, IPAddress Gateway)>();

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;

                var type = ni.NetworkInterfaceType;
                if (type is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                var label = (ni.Name + " " + ni.Description).ToLowerInvariant();
                if (TunnelHints.Any(hint => label.Contains(hint, StringComparison.Ordinal))) continue;

                IPInterfaceProperties props;
                try { props = ni.GetIPProperties(); }
                catch { continue; }

                foreach (var gateway in props.GatewayAddresses)
                {
                    if (gateway.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (gateway.Address.Equals(IPAddress.Any)) continue;
                    if (!IsPrivate(gateway.Address)) continue;

                    candidates.Add((type, ni.Name, gateway.Address));
                }
            }
        }
        catch
        {
            return null;
        }

        // Точка доступа телефона — это именно Wi-Fi, поэтому беспроводной шлюз в приоритете.
        var wireless = candidates.FirstOrDefault(c =>
            c.Type is NetworkInterfaceType.Wireless80211 ||
            c.Name.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) ||
            c.Name.Contains("WiFi", StringComparison.OrdinalIgnoreCase) ||
            c.Name.Contains("Беспроводн", StringComparison.OrdinalIgnoreCase));

        if (wireless.Gateway is not null) return wireless.Gateway.ToString();

        return candidates.Count > 0 ? candidates[0].Gateway.ToString() : null;
    }

    /// <summary>
    /// Запасной способ найти телефон: перебор адресов в подсети ноутбука и проверка,
    /// не отвечает ли там прокси. Нужен, когда шлюз ещё не переключился на точку доступа
    /// или телефон сменил адрес, а DHCP на ноутбуке ещё не обновился.
    /// </summary>
    public static async Task<string?> ScanSubnetForProxyAsync(int port, CancellationToken ct = default)
    {
        var localAddresses = new List<(IPAddress Address, int Prefix)>();

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                var label = (ni.Name + " " + ni.Description).ToLowerInvariant();
                if (TunnelHints.Any(hint => label.Contains(hint, StringComparison.Ordinal))) continue;

                IPInterfaceProperties props;
                try { props = ni.GetIPProperties(); }
                catch { continue; }

                foreach (var ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(ua.Address)) continue;
                    localAddresses.Add((ua.Address, ua.PrefixLength));
                }
            }
        }
        catch
        {
            return null;
        }

        foreach (var (local, prefix) in localAddresses)
        {
            // Больше 24 бит — слишком много адресов для быстрого сканирования.
            if (prefix is < 16 or > 24) continue;

            var found = await ScanRangeAsync(local, prefix, port, ct).ConfigureAwait(false);
            if (found is not null) return found;
        }

        return null;
    }

    private static async Task<string?> ScanRangeAsync(IPAddress local, int prefix, int port, CancellationToken ct)
    {
        var localBytes = local.GetAddressBytes();
        var hostBits = 32 - prefix;
        var range = 1 << hostBits;

        // Небольшие подсети — перебираем целиком. Большие (16 бит) — только «ближайших» соседей.
        var starts = new List<int>();
        var localHost = (localBytes[3] & 0xFF);

        if (range <= 512)
        {
            for (var i = 1; i < range - 1; i++) starts.Add(i);
        }
        else
        {
            // Ограничиваемся окном вокруг нашего адреса — там сидит телефон.
            for (var i = -32; i <= 32; i++)
            {
                if (i == 0) continue;
                var candidate = localHost + i;
                if (candidate is > 0 and < 255) starts.Add(candidate);
            }
        }

        var tasks = new List<Task<string?>>(Math.Min(starts.Count, 64));

        foreach (var hostPart in starts)
        {
            ct.ThrowIfCancellationRequested();

            var bytes = (byte[])localBytes.Clone();
            bytes[3] = (byte)hostPart;
            var candidate = new IPAddress(bytes);

            tasks.Add(CheckHostAsync(candidate, port, ct));
        }

        foreach (var task in tasks)
        {
            var result = await task.ConfigureAwait(false);
            if (result is not null) return result;
        }

        return null;
    }

    private static async Task<string?> CheckHostAsync(IPAddress ip, int port, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient { NoDelay = true };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(700));

            await client.ConnectAsync(ip, port, timeout.Token).ConfigureAwait(false);

            // Порт открыт — проверяем, что это наш прокси (SOCKS5-приветствие).
            await using var stream = client.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);

            var buffer = new byte[2];
            var read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read >= 2 && buffer[0] == 0x05) return ip.ToString();

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsPrivate(IPAddress address)
    {
        var b = address.GetAddressBytes();

        return b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168);
    }
}
