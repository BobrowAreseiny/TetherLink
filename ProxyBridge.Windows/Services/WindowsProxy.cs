using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ProxyBridge.Windows.Services;

/// <summary>
/// Системный прокси Windows (HKCU\...\\Internet Settings) + немедленное уведомление WinINet.
/// HKCU — без прав администратора.
/// </summary>
internal static class WindowsProxy
{
    private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string Override = "<local>;localhost;127.*;10.*;172.16.*;192.168.*";

    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;

    /// <summary>Порт системного прокси (0, если не настроен или это PAC).</summary>
    public static int ServerPort
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
            if (key?.GetValue("ProxyServer") is not string server) return 0;

            foreach (var part in server.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var value = part.Contains('=') ? part[(part.IndexOf('=') + 1)..] : part;
                var colon = value.LastIndexOf(':');
                if (colon > 0 && int.TryParse(value[(colon + 1)..], out var port)) return port;
            }

            return 0;
        }
    }

    /// <summary>
    /// Хост системного прокси (пусто, если не настроен или это PAC).
    /// Важно: прокси живёт на телефоне в точке доступа, поэтому хост — не 127.0.0.1,
    /// и проверять доступность нужно именно по нему.
    /// </summary>
    public static string ServerHost
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
            if (key?.GetValue("ProxyServer") is not string server) return string.Empty;

            foreach (var part in server.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var value = part.Contains('=') ? part[(part.IndexOf('=') + 1)..] : part;
                var colon = value.LastIndexOf(':');
                var host = colon > 0 ? value[..colon] : value;
                if (!string.IsNullOrWhiteSpace(host)) return host.Trim();
            }

            return string.Empty;
        }
    }

    /// <summary>Включает статический прокси. Хост может быть не только 127.0.0.1 (например, IP телефона в сети).</summary>
    public static void Enable(string proxyServer)
    {
        using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true)
            ?? throw new InvalidOperationException("Не удалось открыть ключ Internet Settings.");

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
        key.SetValue("ProxyOverride", Override, RegistryValueKind.String);
        ClearPac(key);
        Refresh();
    }

    /// <summary>Выключает системный прокси и убирает PAC.</summary>
    public static void Disable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true)
            ?? throw new InvalidOperationException("Не удалось открыть ключ Internet Settings.");

        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        ClearPac(key);
        Refresh();
    }

    // ---- Память о том, что включили именно мы ----
    // Нужна, чтобы после аварийного завершения (taskkill) вернуть настройки,
    // даже если прокси указывал не на 127.0.0.1, а на телефон в сети.

    private const string OwnKeyPath = @"Software\ProxyBridge";

    /// <summary>Запоминает включённый нами прокси, чтобы потом откатить его при аварии.</summary>
    public static void SaveOwned(string? proxyServer, string? pacUrl)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(OwnKeyPath);
            if (key is null) return;

            if (string.IsNullOrWhiteSpace(proxyServer)) key.DeleteValue("OwnedProxy", throwOnMissingValue: false);
            else key.SetValue("OwnedProxy", proxyServer, RegistryValueKind.String);

            if (string.IsNullOrWhiteSpace(pacUrl)) key.DeleteValue("OwnedPac", throwOnMissingValue: false);
            else key.SetValue("OwnedPac", pacUrl, RegistryValueKind.String);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] SaveOwned: {ex.Message}");
        }
    }

    /// <summary>Забывает про наши настройки — вызывается после штатного отката.</summary>
    public static void ClearOwned() => SaveOwned(null, null);

    /// <summary>
    /// Включён ли сейчас ровно тот прокси/PAC, который включали мы сами.
    /// true — значит его можно безопасно выключить (наши настройки, а не чужие).
    /// </summary>
    public static bool IsOursActive()
    {
        try
        {
            using var own = Registry.CurrentUser.OpenSubKey(OwnKeyPath);
            if (own is null) return false;

            var ownedProxy = own.GetValue("OwnedProxy") as string;
            var ownedPac = own.GetValue("OwnedPac") as string;

            using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
            if (key is null) return false;

            var currentProxy = key.GetValue("ProxyServer") as string;
            var currentPac = key.GetValue("AutoConfigURL") as string;
            var enabled = key.GetValue("ProxyEnable") is int v && v == 1;

            if (!string.IsNullOrWhiteSpace(ownedPac) && string.Equals(currentPac, ownedPac, StringComparison.OrdinalIgnoreCase))
                return true;

            return enabled
                && !string.IsNullOrWhiteSpace(ownedProxy)
                && string.Equals(currentProxy, ownedProxy, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] IsOursActive: {ex.Message}");
            return false;
        }
    }

    private static void ClearPac(RegistryKey key)
    {
        if (key.GetValue("AutoConfigURL") is not null)
            key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
    }

    private static void Refresh()
    {
        InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }

    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
