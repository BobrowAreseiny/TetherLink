using System.Diagnostics;

namespace ProxyBridge.Windows.Services;

public static class WindowsTtlProtector
{
    /// <summary>
    /// Устанавливает TTL = 65 в Windows, чтобы прямые пакеты в обход прокси
    /// после прохождения хотспота телефона имели TTL = 64 (неотличимо от Android).
    /// </summary>
    public static bool EnableCarrierStealthTtl()
    {
        return RunNetsh("int ipv4 set glob defaultcurhoplimit=65") &&
               RunNetsh("int ipv6 set glob defaultcurhoplimit=65");
    }

    /// <summary>
    /// Возвращает стандартный TTL Windows (128), если нужно откатить настройки.
    /// </summary>
    public static bool RestoreDefaultTtl()
    {
        return RunNetsh("int ipv4 set glob defaultcurhoplimit=128") &&
               RunNetsh("int ipv6 set glob defaultcurhoplimit=128");
    }

    private static bool RunNetsh(string arguments)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.Start();
            process.WaitForExit(3000);
            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ProxyBridge] Failed to set TTL: {ex.Message}");
            return false;
        }
    }
}