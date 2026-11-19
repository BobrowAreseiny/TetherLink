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
    private const string OwnKeyPath = @"Software\ProxyBridge";
    private const string OwnedEnvValue = "OwnedEnv";

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

    /// <summary>
    /// Убирает переменные прокси, оставшиеся от ПРЕДЫДУЩЕГО запуска (например, после
    /// жёсткого taskkill /F — тогда Restore не успел отработать).
    ///
    /// Без этого opencode и git продолжают стучаться в старый IP телефона, которого
    /// в сети уже нет, и «не подключаются» без видимых причин.
    ///
    /// Точный адрес, который мы выставляли, хранится в HKCU\Software\ProxyBridge\OwnedEnv,
    /// поэтому удаляем только свои значения — даже если порт не 9000. Чужие прокси
    /// (корпоративный, VPN) не затрагиваются.
    /// </summary>
    public static bool ClearOrphanedVariables()
    {
        try
        {
            var owned = ReadOwnedEnv();

            using var key = Registry.CurrentUser.OpenSubKey(EnvironmentKeyPath, writable: true);
            if (key is null) return false;

            var removed = false;

            foreach (var name in ProxyVariables)
            {
                var value = key.GetValue(name) as string;
                if (string.IsNullOrWhiteSpace(value)) continue;

                bool isOurs;
                if (name is "no_proxy" or "NO_PROXY")
                {
                    isOurs = value == "localhost,127.0.0.1,::1";
                }
                else if (owned is not null)
                {
                    // Точное совпадение с адресом из прошлой сессии.
                    isOurs = string.Equals(value, owned, StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    // Совместимость со старой версией: раньше порт был только 9000.
                    isOurs = value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                             (value.EndsWith(":9000", StringComparison.OrdinalIgnoreCase) ||
                              value.Contains(":9000/", StringComparison.OrdinalIgnoreCase));
                }

                if (!isOurs) continue;

                key.DeleteValue(name, throwOnMissingValue: false);
                removed = true;
            }

            // Запись об адресе больше не нужна — переменные сняты.
            if (owned is not null) SaveOwnedEnv(null);

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

    private static string? ReadOwnedEnv()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(OwnKeyPath);
            return key?.GetValue(OwnedEnvValue) as string;
        }
        catch
        {
            return null;
        }
    }

    private static void SaveOwnedEnv(string? proxyUrl)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(OwnKeyPath);
            if (key is null) return;

            if (string.IsNullOrWhiteSpace(proxyUrl))
                key.DeleteValue(OwnedEnvValue, throwOnMissingValue: false);
            else
                key.SetValue(OwnedEnvValue, proxyUrl, RegistryValueKind.String);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] SaveOwnedEnv: {ex.Message}");
        }
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

        // Запоминаем точный адрес, чтобы после аварийного завершения убрать
        // из окружения именно его, а не любой чужой прокси.
        SaveOwnedEnv(proxy);

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
            SaveOwnedEnv(null);
            BroadcastEnvironmentChange();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] ProxyEnvironment.Restore: {ex.Message}");
        }
    }

    /// <summary>
    /// ПРИНУДИТЕЛЬНАЯ очистка переменных прокси из HKCU\Environment — независимо от
    /// того, ставили ли мы их в этом запуске. Это «красная кнопка» для кнопки сброса:
    /// работает даже если приложение было перезапущено, убито или переменные
    /// остались от прошлой сессии с телефоном.
    ///
    /// expectedProxy != null — удаляем только это точное значение (наш текущий адрес),
    /// чтобы не стереть чужой корпоративный прокси. null — удаляем любые значения
    /// вида http://host:port (режим полного сброса).
    ///
    /// Возвращает число удалённых переменных.
    /// </summary>
    public static int ForceClear(string? expectedProxy = null)
    {
        var removed = 0;

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(EnvironmentKeyPath, writable: true);
            if (key is null) return 0;

            foreach (var name in ProxyVariables)
            {
                // no_proxy — это список исключений, а не адрес: убираем тоже,
                // но только если он совпадает с нашим шаблоном.
                var value = key.GetValue(name) as string;
                if (string.IsNullOrWhiteSpace(value)) continue;

                bool isOurs;
                if (name is "no_proxy" or "NO_PROXY")
                {
                    isOurs = value == "localhost,127.0.0.1,::1";
                }
                else if (expectedProxy is not null)
                {
                    isOurs = string.Equals(value, expectedProxy, StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    isOurs = value.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
                }

                if (!isOurs) continue;

                key.DeleteValue(name, throwOnMissingValue: false);
                Interlocked.Exchange(ref _applied, 0);
                removed++;
            }

            _previous.Clear();

            if (removed > 0)
            {
                SaveOwnedEnv(null);
                BroadcastEnvironmentChange();
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] ForceClear: {ex.Message}");
        }

        return removed;
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
