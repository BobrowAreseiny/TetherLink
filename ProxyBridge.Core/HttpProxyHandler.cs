using System.Net;
using System.Text;
using ProxyBridge.Core.Abstractions;

namespace ProxyBridge.Core;

/// <summary>
/// HTTP/1.x: CONNECT (HTTPS-туннель) + абсолютные запросы (GET http://host/..., POST ...).
/// </summary>
internal static class HttpProxyHandler
{
    private const int MaxHeadBytes = 64 * 1024;

    public static async Task HandleAsync(Stream client, IAuthValidator? auth, IStatsSink? stats, long id, Action<string>? log, CancellationToken ct, IPAddress? pacHost = null, int pacPort = 0)
    {
        var (head, leftover) = await ReadHeadAsync(client, ct).ConfigureAwait(false);
        var request = HttpRequestHead.Parse(head);

        var clientCounter = new CountingStream(client);

        // PAC-файл отдаём без аутентификации: клиент должен получить его до того,
        // как начнёт слать учётные данные (иначе автонастройка не работает).
        if (pacHost is not null && PacService.IsPacRequest(request.Target))
        {
            var response = PacService.BuildPacResponse(pacHost, pacPort);
            await client.WriteAsync(response, ct).ConfigureAwait(false);
            log?.Invoke("PAC запрошен клиентом");
            return;
        }

        if (auth is not null && !CheckAuth(request, auth))
        {
            await WriteAsync(client, "HTTP/1.1 407 Proxy Authentication Required\r\n" +
                                     "Proxy-Authenticate: Basic realm=\"ProxyBridge\"\r\n" +
                                     "Content-Length: 0\r\nConnection: close\r\n\r\n", ct).ConfigureAwait(false);
            return;
        }

        if (request.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            var (host, port) = ParseAuthority(request.Target, 443);
            await TunnelAsync(clientCounter, host, port, stats, id, log, ct).ConfigureAwait(false);
            Report(stats, id, clientCounter);
            return;
        }
        if (!Uri.TryCreate(request.Target, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp)
        {
            await WriteAsync(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", ct).ConfigureAwait(false);
            return;
        }

        await ForwardAsync(clientCounter, request, uri, leftover, stats, id, log, ct).ConfigureAwait(false);
        Report(stats, id, clientCounter);
    }

    /// <summary>Живой отчёт о трафике внутри одной сессии (вызывается из Relay).</summary>
    private static Action ProgressReporter(IStatsSink? stats, long id, CountingStream counter)
        => () => stats?.ReportAbsolute(id, counter.BytesRead, counter.BytesWritten);

    private static void Report(IStatsSink? stats, long id, CountingStream counter)
        => stats?.ReportAbsolute(id, counter.BytesRead, counter.BytesWritten);

    private static async Task ForwardAsync(Stream client, HttpRequestHead request, Uri uri, byte[] leftover,
            IStatsSink? stats, long id, Action<string>? log, CancellationToken ct)
    {
        var host = uri.Host;

        // ==========================================
        // 1. Блокируем телеметрию и обновления Windows
        // ==========================================
        if (CarrierStealthFilter.ShouldBlockHost(host))
        {
            log?.Invoke($"Заблокирован хост телеметрии: {host}");
            return; // Тихо завершаем соединение
        }

        var port = uri.IsDefaultPort ? 80 : uri.Port;

        using var upstream = await Relay.ConnectAsync(host, port, ct).ConfigureAwait(false);

        // ==========================================
        // 2. Принудительно ставим TTL = 64 для исходящего сокета
        // ==========================================
        CarrierStealthFilter.ApplyStealthSocketOptions(upstream.Client);

        await using var toUpstream = upstream.GetStream();

        var sb = new StringBuilder();
        var path = uri.PathAndQuery;
        sb.Append(request.Method).Append(' ').Append(path).Append(' ').Append(request.Version).Append("\r\n");

        var hasHost = false;
        foreach (var (name, value) in request.Headers)
        {
            if (name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Connection", StringComparison.OrdinalIgnoreCase))
                continue;

            // ==========================================
            // 3. Маскируем десктопный User-Agent под мобильный Android
            // ==========================================
            var headerValue = value;
            if (name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase) &&
                (value.Contains("Windows NT", StringComparison.OrdinalIgnoreCase) ||
                 value.Contains("Macintosh", StringComparison.OrdinalIgnoreCase) ||
                 value.Contains("Microsoft NCSI", StringComparison.OrdinalIgnoreCase)))
            {
                headerValue = "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36";
            }

            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) hasHost = true;
            sb.Append(name).Append(": ").Append(headerValue).Append("\r\n");
        }

        if (!hasHost) sb.Append("Host: ").Append(uri.IsDefaultPort ? uri.Host : uri.Authority).Append("\r\n");
        sb.Append("Connection: close\r\n\r\n");

        await WriteAsync(toUpstream, sb.ToString(), ct).ConfigureAwait(false);
        if (leftover.Length > 0)
            await toUpstream.WriteAsync(leftover, ct).ConfigureAwait(false);

        log?.Invoke($"HTTP {request.Method} {uri.Host}:{port}{path}");
        await Relay.PipeAsync(client, toUpstream, ct, onProgress: ProgressReporter(stats, id, (CountingStream)client)).ConfigureAwait(false);
    }

    private static async Task TunnelAsync(Stream client, string host, int port, IStatsSink? stats, long id, Action<string>? log, CancellationToken ct)
    {
        // ==========================================
        // 1. Блокируем CONNECT-запросы к серверам телеметрии Windows/Apple
        // ==========================================
        if (CarrierStealthFilter.ShouldBlockHost(host))
        {
            log?.Invoke($"Заблокирован HTTPS-туннель телеметрии: {host}");
            return;
        }

        using var upstream = await Relay.ConnectAsync(host, port, ct).ConfigureAwait(false);

        // ==========================================
        // 2. Принудительно ставим TTL = 64 для HTTPS-туннеля
        // ==========================================
        CarrierStealthFilter.ApplyStealthSocketOptions(upstream.Client);

        await using var toUpstream = upstream.GetStream();

        await WriteAsync(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: ProxyBridge\r\n\r\n", ct).ConfigureAwait(false);

        log?.Invoke($"CONNECT {host}:{port}");
        await Relay.PipeAsync(client, toUpstream, ct, onProgress: ProgressReporter(stats, id, (CountingStream)client)).ConfigureAwait(false);
    }

    private static bool CheckAuth(HttpRequestHead request, IAuthValidator auth)
    {
        var header = request.Headers.FirstOrDefault(h => h.Name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)).Value;
        if (string.IsNullOrEmpty(header)) return false;

        const string prefix = "Basic ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;

        try
        {
            var raw = Encoding.UTF8.GetString(Convert.FromBase64String(header[prefix.Length..].Trim()));
            var sep = raw.IndexOf(':');
            if (sep < 0) return auth.Validate(raw, string.Empty);
            return auth.Validate(raw[..sep], raw[(sep + 1)..]);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static (string Host, int Port) ParseAuthority(string authority, int defaultPort)
    {
        var idx = authority.LastIndexOf(':');
        if (idx <= 0) return (authority, defaultPort);
        return int.TryParse(authority[(idx + 1)..], out var port)
            ? (authority[..idx], port)
            : (authority, defaultPort);
    }

    private static Task WriteAsync(Stream stream, string text, CancellationToken ct)
        => stream.WriteAsync(Encoding.ASCII.GetBytes(text), ct).AsTask();

    private static async Task<(string Head, byte[] Leftover)> ReadHeadAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[8 * 1024];
        using var acc = new MemoryStream(1024);

        while (true)
        {
            var n = await stream.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (n == 0) throw new IOException("Клиент закрыл соединение до конца заголовков.");

            acc.Write(buffer, 0, n);

            var data = acc.GetBuffer();
            var length = (int)acc.Length;
            var end = IndexOfHeadEnd(data, length);
            if (end >= 0)
            {
                var head = Encoding.ASCII.GetString(data, 0, end);
                var leftover = data.AsSpan(end, length - end).ToArray();
                return (head, leftover);
            }

            if (length > MaxHeadBytes) throw new InvalidDataException("Слишком большой HTTP-заголовок.");
        }
    }

    private static int IndexOfHeadEnd(byte[] data, int length)
    {
        for (var i = 3; i < length; i++)
        {
            if (data[i] == (byte)'\n' && data[i - 1] == (byte)'\r' && data[i - 2] == (byte)'\n' && data[i - 3] == (byte)'\r')
                return i + 1;
        }
        return -1;
    }
}

internal sealed class HttpRequestHead
{
    public required string Method { get; init; }
    public required string Target { get; init; }
    public required string Version { get; init; }
    public List<(string Name, string Value)> Headers { get; } = [];

    public static HttpRequestHead Parse(string head)
    {
        var lines = head.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0) throw new InvalidDataException("Пустой HTTP-запрос.");

        var parts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) throw new InvalidDataException($"Некорректная строка запроса: {lines[0]}");

        var result = new HttpRequestHead { Method = parts[0], Target = parts[1], Version = parts[2] };

        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0) break;
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            result.Headers.Add((line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }

        return result;
    }
}
