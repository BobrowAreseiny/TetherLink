using System.Diagnostics;

namespace ProxyBridge.Windows.Services;

/// <summary>
/// Завершение уже запущенной сессии OpenCode при смене прокси-настроек.
///
/// OpenCode (Bun/Electron) читает http_proxy/https_proxy только при старте процесса.
/// Если он уже работает, после подключения/отключения прокси его запросы уходят
/// в несуществующий адрес, и пользователь видит «ошибка сети». Поэтому при смене
/// настроек сессию завершаем: следующий запуск подхватит актуальные переменные.
///
/// Приложение заново не запускается — это осознанное решение: не навязываем
/// пользователю открытие OpenCode и не плодим фоновые процессы.
/// </summary>
internal static class OpencodeSession
{
    /// <summary>Включено ли автоматическое завершение сессии (переключатель в настройках).</summary>
    public static bool Enabled { get; set; } = true;

    private static readonly string[] ProcessNames =
    [
        "OpenCode",       // окно Desktop (Electron)
        "opencode-cli",   // фоновая служба (serve --service)
        "opencode-pty",   // терминальный хост
    ];

    private static int _closing;

    /// <summary>Запущена ли сейчас какая-либо часть OpenCode.</summary>
    public static bool IsRunning =>
        ProcessNames.Any(name => Process.GetProcessesByName(name).Length > 0);

    /// <summary>
    /// Завершает OpenCode, если он запущен. Возвращает true, если процесс был
    /// найден и завершён. Безопасно вызывать из любого потока.
    /// </summary>
    public static bool TerminateIfRunning(string reason)
    {
        if (!Enabled) return false;
        if (Interlocked.Exchange(ref _closing, 1) == 1) return false;

        try
        {
            var running = ProcessNames
                .SelectMany(Process.GetProcessesByName)
                .ToList();

            if (running.Count == 0) return false;

            ProxySession.AppendLog($"Закрываю сессию OpenCode ({reason}) — при следующем запуске он прочитает актуальные настройки прокси");

            // 1. Мягкое закрытие окна — Electron успевает сохранить состояние.
            foreach (var p in running.Where(p => p.MainWindowHandle != IntPtr.Zero))
            {
                try { p.CloseMainWindow(); } catch { /* уже закрывается */ }
            }

            // 2. Даём секунду на штатный выход, затем завершаем остатки.
            Thread.Sleep(900);

            foreach (var name in ProcessNames)
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try { p.Kill(); } catch { /* уже вышел */ }
                }
            }

            ProxySession.AppendLog("Сессия OpenCode завершена");
            return true;
        }
        catch (Exception ex)
        {
            ProxySession.AppendLog($"Не удалось завершить OpenCode: {ex.Message}");
            return false;
        }
        finally
        {
            Interlocked.Exchange(ref _closing, 0);
        }
    }
}
