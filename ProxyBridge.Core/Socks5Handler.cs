using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyBridge.Core.Abstractions;

namespace ProxyBridge.Core;

/// <summary>
/// SOCKS5 (RFC 1928) + username/password (RFC 1929) + UDP ASSOCIATE.
/// </summary>
internal static class Socks5Handler
{
    private const byte Version = 0x05;

    public static async Task HandleAsync(Stream client, IAuthValidator? auth, IStatsSink? stats, long id, Action<string>? log, CancellationToken ct)
    {
        var counter = new CountingStream(client);
        await HandleCoreAsync(counter, auth, stats, id, log, ct).ConfigureAwait(false);
        // Абсолютные значения: дельты счётчик посчитает сам, без задвоения с живым отчётом.
        stats?.ReportAbsolute(id, counter.BytesRead, counter.BytesWritten);
    }

    private static async Task HandleCoreAsync(Stream client, IAuthValidator? auth, IStatsSink? stats, long id, Action<string>? log, CancellationToken ct)
    {
        // 1) greeting: VER, NMETHODS, METHODS
        var head = new byte[2];
        if (!await ReadExactAsync(client, head, ct).ConfigureAwait(false)) return;
        if (head[0] != Version) return;

        var methods = new byte[head[1]];
        if (!await ReadExactAsync(client, methods, ct).ConfigureAwait(false)) return;

        var useAuth = auth is not null && methods.Contains((byte)0x02);
        if (auth is not null && !useAuth)
        {
            await client.WriteAsync(new byte[] { Version, 0xFF }, ct).ConfigureAwait(false);
            return;
        }

        await client.WriteAsync(new byte[] { Version, useAuth ? (byte)0x02 : (byte)0x00 }, ct).ConfigureAwait(false);

        if (useAuth && !await AuthenticateAsync(client, auth!, ct).ConfigureAwait(false))
            return;

        // 2) request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
        var req = new byte[4];
        if (!await ReadExactAsync(client, req, ct).ConfigureAwait(false)) return;
        if (req[0] != Version)
        {
            await ReplyAsync(client, 0x01, ct).ConfigureAwait(false);
            return;
        }

        if (req[1] != 0x01 && req[1] != 0x03)
        {
            await ReplyAsync(client, 0x07, ct).ConfigureAwait(false); // Command not supported
            return;
        }

        // Адресную часть читаем всегда — и для CONNECT, и для UDP ASSOCIATE.
        // Иначе в сокете остаются непрочитанные байты, и при закрытии клиент
        // получает RST вместо ответа.
        string host;
        switch (req[3])
        {
            case 0x01: // IPv4
            {
                var ip = new byte[4];
                if (!await ReadExactAsync(client, ip, ct).ConfigureAwait(false)) return;
                host = new IPAddress(ip).ToString();
                break;
            }
            case 0x03: // domain
            {
                var len = new byte[1];
                if (!await ReadExactAsync(client, len, ct).ConfigureAwait(false)) return;
                var name = new byte[len[0]];
                if (!await ReadExactAsync(client, name, ct).ConfigureAwait(false)) return;
                host = Encoding.ASCII.GetString(name);
                break;
            }
            case 0x04: // IPv6
            {
                var ip = new byte[16];
                if (!await ReadExactAsync(client, ip, ct).ConfigureAwait(false)) return;
                host = new IPAddress(ip).ToString();
                break;
            }
            default:
                await ReplyAsync(client, 0x08, ct).ConfigureAwait(false); // Address type not supported
                return;
        }

        var portBytes = new byte[2];
        if (!await ReadExactAsync(client, portBytes, ct).ConfigureAwait(false)) return;
        var port = (portBytes[0] << 8) | portBytes[1];

        // ==========================================
        // Жёсткая защита: не пускаем SOCKS5 к десктопным целям и не соединяемся без маскировки сокета
        // ==========================================
        if (CarrierStealthFilter.ShouldBlockHost(host))
        {
            log?.Invoke($"Заблокирован SOCKS5-туннель телеметрии: {host}");
            await ReplyAsync(client, 0x05, ct).ConfigureAwait(false); // Connection refused
            return;
        }

        if (req[1] == 0x03) // UDP ASSOCIATE
        {
            await HandleUdpAssociateAsync(client, ct, log).ConfigureAwait(false);
            return;
        }

        TcpClient upstream;
        try
        {
            upstream = await Relay.ConnectAsync(host, port, ct).ConfigureAwait(false);
            // Принудительная маскировка сокета перед передачей трафика оператору
            CarrierStealthFilter.ApplyStealthSocketOptions(upstream.Client);
        }
        catch (Exception ex)
        {
            log?.Invoke($"SOCKS5 connect {host}:{port} failed: {ex.Message}");
            await ReplyAsync(client, 0x05, ct).ConfigureAwait(false); // Connection refused
            return;
        }

        using (upstream)
        {
            await using var toUpstream = upstream.GetStream();
            await ReplyAsync(client, 0x00, ct).ConfigureAwait(false);

            log?.Invoke($"SOCKS5 {host}:{port}");
            await Relay.PipeAsync(client, toUpstream, ct, onProgress: ReportProgress(stats, id, client)).ConfigureAwait(false);
        }
    }

    /// <summary>Живой отчёт о трафике внутри одной сессии (вызывается из Relay).</summary>
    private static Action ReportProgress(IStatsSink? stats, long id, Stream client)
        => () =>
        {
            if (client is CountingStream counter)
                stats?.ReportAbsolute(id, counter.BytesRead, counter.BytesWritten);
        };

    private static async Task<bool> AuthenticateAsync(Stream client, IAuthValidator auth, CancellationToken ct)
    {
        var head = new byte[2];
        if (!await ReadExactAsync(client, head, ct).ConfigureAwait(false)) return false;

        var user = new byte[head[1]];
        if (!await ReadExactAsync(client, user, ct).ConfigureAwait(false)) return false;

        var passLen = new byte[1];
        if (!await ReadExactAsync(client, passLen, ct).ConfigureAwait(false)) return false;

        var pass = new byte[passLen[0]];
        if (!await ReadExactAsync(client, pass, ct).ConfigureAwait(false)) return false;

        var ok = auth.Validate(Encoding.UTF8.GetString(user), Encoding.UTF8.GetString(pass));
        await client.WriteAsync(new byte[] { 0x01, ok ? (byte)0x00 : (byte)0x01 }, ct).ConfigureAwait(false);
        return ok;
    }

    /// <summary>
    /// UDP ASSOCIATE: поднимаем UDP-сокет на том же адресе, что и TCP-listener,
    /// сообщаем клиенту его адрес и переливаем датаграммы туда-сюда.
    /// Сеанс живёт, пока открыто управляющее TCP-соединение.
    /// </summary>
    private static async Task HandleUdpAssociateAsync(Stream client, CancellationToken ct, Action<string>? log)
    {
        UdpClient? relay = null;
        CancellationTokenSource? linked = null;
        try
        {
            // Сокет лежит внутри счётчика — достаём исходный NetworkStream.
            var raw = client is CountingStream counter ? counter.Inner : client;
            var ns = raw as NetworkStream;

            // BND.ADDR должен совпадать с адресом, по которому клиент пришёл.
            var local = ns?.Socket?.LocalEndPoint as IPEndPoint;
            var bindAddress = local?.Address ?? IPAddress.Any;

            relay = new UdpClient(new IPEndPoint(bindAddress, 0));

            var advertised = local?.Address ?? IPAddress.Any;
            var port = (relay.Client.LocalEndPoint as IPEndPoint)?.Port ?? 0;

            await ReplyAsync(client, 0x00, advertised, port, ct).ConfigureAwait(false);
            log?.Invoke($"SOCKS5 UDP ASSOCIATE → {advertised}:{port}");

            var clientEndPoint = ns?.Socket?.RemoteEndPoint as IPEndPoint;
            if (clientEndPoint is null) return;

            // Закрытие управляющего TCP-соединения = конец UDP-сеанса (RFC 1928).
            linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var relayToken = linked.Token;
            _ = WatchControlConnectionAsync(client, linked, relayToken);

            await Socks5Udp.RelayAsync(relay, clientEndPoint.Address, relayToken, log).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Invoke($"SOCKS5 UDP ASSOCIATE failed: {ex.Message}");
        }
        finally
        {
            try { linked?.Cancel(); } catch { /* уже отменён */ }
            linked?.Dispose();
            relay?.Dispose();
        }
    }

    /// <summary>
    /// Ждёт закрытия управляющего TCP-соединения. Клиент может прислать байты — они
    /// игнорируются (по RFC в этом канале данных нет), важен только факт закрытия.
    /// </summary>
    private static async Task WatchControlConnectionAsync(Stream client, CancellationTokenSource owner, CancellationToken ct)
    {
        var buffer = new byte[256];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var n = await client.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
                if (n == 0) break; // клиент закрыл соединение
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        catch (Exception) { }
        finally
        {
            try { owner.Cancel(); } catch { /* уже отменён */ }
        }
    }

    private static async Task ReplyAsync(Stream client, byte code, CancellationToken ct)
        => await ReplyAsync(client, code, IPAddress.Any, 0, ct).ConfigureAwait(false);

    private static async Task ReplyAsync(Stream client, byte code, IPAddress address, int port, CancellationToken ct)
    {
        // ATYP подбирается по семейству адреса: IPv4 → 1, IPv6 → 4. Иначе 16 байт
        // уезжали под видом IPv4 и клиент не мог разобрать ответ.
        var isV4 = address.AddressFamily == AddressFamily.InterNetwork;
        var atyp = isV4 ? 0x01 : 0x04;

        var reply = new byte[] { Version, code, 0x00, (byte)atyp };
        reply = [.. reply, .. address.GetAddressBytes(), (byte)(port >> 8), (byte)(port & 0xFF)];
        await client.WriteAsync(reply, ct).ConfigureAwait(false);
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(offset), ct).ConfigureAwait(false);
            if (n == 0) return false;
            offset += n;
        }
        return true;
    }
}
