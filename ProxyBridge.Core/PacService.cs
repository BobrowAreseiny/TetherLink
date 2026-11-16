using System.Net;
using System.Text;

namespace ProxyBridge.Core;

/// <summary>
/// Генератор PAC-файла (Proxy Auto-Config) и разбор запросов к нему.
/// Клиент (Windows/macOS/Linux/Android) получает PAC по адресу
/// http://&lt;ip-телефона&gt;:&lt;порт&gt;/proxy.pac и сам настраивает прокси.
/// </summary>
public static class PacService
{
    /// <summary>Пути, на которых прокси отдаёт PAC-файл.</summary>
    public static readonly string[] PacPaths = ["/proxy.pac", "/wpad.dat", "/proxy.pac.txt"];

    /// <summary>Хост, который клиент использует для WPAD-поиска: «wpad».</summary>
    public const string WpadHost = "wpad";

    /// <summary>
    /// Собирает PAC: весь внешний трафик — через прокси, локальные адреса — напрямую.
    /// SOCKS5 идёт вторым в списке, чтобы клиент, не умеющий HTTP, откатился на него.
    /// </summary>
    public static string BuildPac(IPAddress proxyAddress, int port)
    {
        var host = proxyAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{proxyAddress}]"
            : proxyAddress.ToString();

        var sb = new StringBuilder();
        sb.AppendLine("// ProxyBridge — автонастройка прокси (PAC)");
        sb.AppendLine("// Сгенерирован автоматически. Не редактировать.");
        sb.AppendLine("function FindProxyForURL(url, host) {");
        sb.AppendLine("  host = host.toLowerCase();");
        sb.AppendLine("  if (isPlainHostName(host) ||");
        sb.AppendLine("      shExpMatch(host, \"localhost\") ||");
        sb.AppendLine("      shExpMatch(host, \"*.local\") ||");
        sb.AppendLine("      shExpMatch(host, \"*.localhost\") ||");
        sb.AppendLine("      isInNet(dnsResolve(host), \"127.0.0.0\", \"255.0.0.0\") ||");
        sb.AppendLine("      isInNet(dnsResolve(host), \"10.0.0.0\", \"255.0.0.0\") ||");
        sb.AppendLine("      isInNet(dnsResolve(host), \"172.16.0.0\", \"255.0.0.0\") ||");
        sb.AppendLine("      isInNet(dnsResolve(host), \"192.168.0.0\", \"255.255.0.0\") ||");
        sb.AppendLine("      isInNet(dnsResolve(host), \"169.254.0.0\", \"255.255.0.0\")) {");
        sb.AppendLine("    return \"DIRECT\";");
        sb.AppendLine("  }");
        sb.AppendLine($"  return \"PROXY {host}:{port}; SOCKS5 {host}:{port}\";");
        sb.AppendLine("}");
        return sb.ToString();
    }

    /// <summary>Проверяет, что запрос адресован к PAC-файлу (по origin-form или absolute-form).</summary>
    public static bool IsPacRequest(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;

        // origin-form: GET /proxy.pac HTTP/1.1
        if (target.StartsWith('/')) return PacPaths.Any(p => target.Equals(p, StringComparison.OrdinalIgnoreCase));

        // absolute-form: GET http://host/proxy.pac HTTP/1.1
        if (Uri.TryCreate(target, UriKind.Absolute, out var uri))
            return PacPaths.Any(p => uri.AbsolutePath.Equals(p, StringComparison.OrdinalIgnoreCase));

        return false;
    }

    /// <summary>Собирает HTTP-ответ с PAC-файлом.</summary>
    public static byte[] BuildPacResponse(IPAddress proxyAddress, int port)
    {
        var pac = BuildPac(proxyAddress, port);
        var body = Encoding.UTF8.GetBytes(pac);
        var head = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/x-ns-proxy-autoconfig\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Cache-Control: no-store\r\n" +
            "Connection: close\r\n\r\n");

        var result = new byte[head.Length + body.Length];
        Buffer.BlockCopy(head, 0, result, 0, head.Length);
        Buffer.BlockCopy(body, 0, result, head.Length, body.Length);
        return result;
    }
}
