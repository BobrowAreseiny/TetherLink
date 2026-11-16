using Microsoft.Win32;

namespace ProxyBridge.Windows.Services;

/// <summary>
/// Переменные окружения HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY для текущего пользователя.
///
/// Зачем это нужно: системный прокси Windows (WinINET) читают браузеры, но не читают
/// Node/Bun/Electron-приложения — opencode, git, npm, docker, pip. Они смотрят только
/// на переменные окружения. Поэтому при подключении мы выставляем их автоматически,
/// а при отключении — возвращаем то, что было до нас.
///
/// Важно про регистр: Bun (на чём написан opencode) читает только НИЖНИЙ регистр
/// (http_proxy / https_proxy) — с HTTP_PROXY он всё равно идёт мимо прокси.
/// Поэтому lowercase — основные, а верхний регистр ставим тоже: его читают git, npm, curl.
///
/// Переменные пишутся в HKCU\Environment, поэтому «зацепить» их может только процесс,
/// запущенный после этого (новый терминал, свежий opencode). Уже запущенные
/// приложения переменные не подхватывают — это особенность Windows, а не ошибка.
/// </summary>
internal static class ProxyEnvironment
{
    private const string EnvironmentKeyPath = @"Environment";

    // Порядок важен: сначала нижний регистр (его читает Bun/opencode), потом верхний.
    private static readonly string[] ProxyVariables =
    [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ];

    // Что было до нас — чтобы вернуть как было, а не просто стереть.
    private static readonly Dictionary<string, string?> _previous = [];
    private static int _applied;

    /// <summary>Какие переменные сейчас выставлены нами (для интерфейса и журнала).</summary>
    public static bool IsApplied => Interlocked.Exchange(ref _applied, 0) == 1;

    /// <summary>
    /// Убирает переменные прокси, оставшиеся от ПРЕДЫДУЩЕГО запуска (например, после
    /// жёсткого taskkill /F — тогда Restore не успел отработать).
    ///
    /// Без этого opencode и git продолжают стучаться в адрес телефона, которого
    /// в сети уже нет, и «не подключаются» без всяких видимых причин.
    ///
    /// Удаляем только те переменные, которые сами выставляем (значение вида
    /// http://host:port), и только если они ещё указывают на тот же адрес.
    /// </summary>
    public static bool ClearOrphanedVariables()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(EnvironmentKeyPath, writable: true);
            if (key is null) return false;

            var removed = false;

            foreach (var name in ProxyVariables)
            {
                var value = key.GetValue(name) as string;
                if (string.IsNullOrWhiteSpace(value)) continue;

                // Только наши значения: http://host:port
                if (!value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) continue;
                if (!value.EndsWith(":9000", StringComparison.OrdinalIgnoreCase) &&
                    !value.Contains(":9000/", StringComparison.OrdinalIgnoreCase)) continue;

                // no_proxy мы не трогаем — это настройка исключений, а не адрес.
                if (name is "no_proxy" or "NO_PROXY") continue;

                key.DeleteValue(name, throwOnMissingValue: false);
                removed = true;
            }

            if (removed)
            {
                BroadcastEnvironmentChange();
                return true;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] ClearOrphanedVariables: {ex.Message}");
        }

        return false;
    }

    /// <summary>
    /// Ставит переменные прокси для пользователя. Значение должно быть вида http://host:port.
    /// </summary>
    public static void Apply(string host, int port)
    {
        var proxy = $"http://{host}:{port}";
        var noProxy = "localhost,127.0.0.1,::1";

        using var key = Registry.CurrentUser.OpenSubKey(EnvironmentKeyPath, writable: true)
            ?? throw new InvalidOperationException("Не удалось открыть ключ Environment.");

        foreach (var name in ProxyVariables)
        {
            var value = name is "NO_PROXY" or "no_proxy" ? noProxy : proxy;

            // Запоминаем прежнее значение только один раз (при первом применении),
            // иначе повторный Apply перезаписал бы «эталон» на наше же значение.
            if (!_previous.ContainsKey(name))
                _previous[name] = key.GetValue(name) as string;

            key.SetValue(name, value, RegistryValueKind.String);
        }

        Interlocked.Exchange(ref _applied, 1);

        BroadcastEnvironmentChange();
    }

    /// <summary>
    /// Возвращает переменные к состоянию до Apply. Если переменной раньше не было — удаляем её.
    /// </summary>
    public static void Restore()
    {
        if (Interlocked.Exchange(ref _applied, 0) == 0) return;

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(EnvironmentKeyPath, writable: true);
            if (key is null) return;

            foreach (var (name, previous) in _previous)
            {
                if (previous is null)
                    key.DeleteValue(name, throwOnMissingValue: false);
                else
                    key.SetValue(name, previous, RegistryValueKind.String);
            }

            _previous.Clear();
            BroadcastEnvironmentChange();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] ProxyEnvironment.Restore: {ex.Message}");
        }
    }

    /// <summary>
    /// Читает текущее значение переменной пользователя (для показа в журнале).
    /// </summary>
    public static string? ReadUserVariable(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(EnvironmentKeyPath);
        return key?.GetValue(name) as string;
    }

    /// <summary>
    /// Сообщает запущенным программам, что окружение изменилось (WM_SETTINGCHANGE).
    /// Уже запущенные процессы это всё равно не подхватывают, но новые — да.
    /// </summary>
    private static void BroadcastEnvironmentChange()
    {
        try
        {
            NativeMethods.SendMessageTimeout(
                new IntPtr(0xffff), // HWND_BROADCAST
                0x001A,            // WM_SETTINGCHANGE
                new IntPtr(0),
                "Environment",
                0x0002,            // SMTO_ABORTIFHUNG
                2000,
                out _);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] BroadcastEnvironmentChange: {ex.Message}");
        }
    }
}
