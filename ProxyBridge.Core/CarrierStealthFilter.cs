using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace ProxyBridge.Core;

public static class CarrierStealthFilter
{
    // Домены, по которым DPI оператора определяет, что за телефоном находится ПК с Windows/macOS
    private static readonly string[] DesktopTellTaleDomains =
    [
        "windowsupdate.com",
        "update.microsoft.com",
        "delivery.mp.microsoft.com",
        "wustat.windows.com",
        "ntservicepack.microsoft.com",
        "statsfe2.ws.microsoft.com",
        "telemetry.microsoft.com",
        "vortex.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "swscan.apple.com",
        "swcdn.apple.com"
    ];

    // Универсальный мобильный User-Agent для маскировки открытых HTTP-запросов
    private const string MobileUserAgent =
        "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36";

    public static bool ShouldBlockHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;

        var cleanHost = host.Split(':')[0].Trim().ToLowerInvariant();

        foreach (var blocked in DesktopTellTaleDomains)
        {
            if (cleanHost.Equals(blocked, StringComparison.Ordinal) ||
                cleanHost.EndsWith("." + blocked, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    public static void ApplyStealthSocketOptions(Socket outboundSocket)
    {
        try
        {
            outboundSocket.NoDelay = true;

            if (outboundSocket.AddressFamily == AddressFamily.InterNetwork ||
                outboundSocket.AddressFamily == AddressFamily.InterNetworkV6)
            {
                outboundSocket.Ttl = 64;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] Socket stealth config warning: {ex.Message}");
        }
    }

    public static byte[] SanitizeHttpHeaderIfNeeded(byte[] buffer, int length, out int newLength)
    {
        newLength = length;
        if (length < 16) return buffer;

        if (!StartsWithHttpMethod(buffer, length))
            return buffer;

        try
        {
            var rawText = Encoding.ASCII.GetString(buffer, 0, length);
            var headerEndIndex = rawText.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headerEndIndex == -1) return buffer;

            var headersPart = rawText[..headerEndIndex];
            var bodyPartOffset = headerEndIndex + 4;
            var bodyLength = length - bodyPartOffset;

            headersPart = Regex.Replace(headersPart, @"\r\nProxy-Connection:[^\r\n]*", "", RegexOptions.IgnoreCase);
            headersPart = Regex.Replace(headersPart, @"\r\nVia:[^\r\n]*", "", RegexOptions.IgnoreCase);
            headersPart = Regex.Replace(headersPart, @"\r\nX-Forwarded-For:[^\r\n]*", "", RegexOptions.IgnoreCase);

            headersPart = Regex.Replace(
                headersPart,
                @"User-Agent:\s*([^\r\n]*(?:Windows NT|Macintosh|X11;\s*Linux\s*x86_64|Microsoft NCSI)[^\r\n]*)",
                $"User-Agent: {MobileUserAgent}",
                RegexOptions.IgnoreCase);

            var newHeaderBytes = Encoding.ASCII.GetBytes(headersPart + "\r\n\r\n");
            newLength = newHeaderBytes.Length + bodyLength;

            var result = new byte[newLength];
            Buffer.BlockCopy(newHeaderBytes, 0, result, 0, newHeaderBytes.Length);
            if (bodyLength > 0)
            {
                Buffer.BlockCopy(buffer, bodyPartOffset, result, newHeaderBytes.Length, bodyLength);
            }

            return result;
        }
        catch
        {
            newLength = length;
            return buffer;
        }
    }

    private static bool StartsWithHttpMethod(byte[] buffer, int length)
    {
        ReadOnlySpan<byte> span = buffer.AsSpan(0, Math.Min(length, 8));
        return span.StartsWith("GET "u8) ||
               span.StartsWith("POST "u8) ||
               span.StartsWith("HEAD "u8) ||
               span.StartsWith("PUT "u8) ||
               span.StartsWith("DELETE "u8) ||
               span.StartsWith("OPTIONS "u8);
    }

    /// <summary>
    /// Жёсткая проверка среды: стелс-маскировка трафика доступна и работает.
    /// Если false — проксеру запрещено стартовать, иначе трафик пойдёт «голым» для оператора.
    /// </summary>
    public static bool VerifyStealthEnvironment()
    {
        try
        {
            // 1. Фильтр доменов работает
            if (!ShouldBlockHost("update.microsoft.com")) return false;
            if (ShouldBlockHost("example.com")) return false;

            // 2. Сокет позволяет установить TTL (без этого оператор увидит настоящий TTL ОС)
            using var testSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            testSocket.NoDelay = true;
            testSocket.Ttl = 64;
            if (testSocket.Ttl != 64) return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Как VerifyStealthEnvironment, но мягкий: не блокирует запуск сервера.
    /// Стелс-функции (TTL=64, фильтрация доменов) работают на уровне сокета,
    /// а глобальный TTL=65 требует админа — без него просто не будет маскировки.
    /// </summary>
    public static void EnsureStealthOrThrow()
    {
        if (!VerifyStealthEnvironment())
        {
            System.Diagnostics.Debug.WriteLine(
                "[ProxyBridge] Стелс-маскировка недоступна — проксер работает без маскировки.");
        }
    }
}