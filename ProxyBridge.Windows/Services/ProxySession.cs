using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ProxyBridge.Core;

namespace ProxyBridge.Windows.Services;

/// <summary>
/// Жизненный цикл подключения на ноутбуке. Режим один — телефон в режиме точки доступа.
///
/// Правило, ради которого всё переписано: системный прокси Windows включается
/// ТОЛЬКО после того, как сквозная проверка канала прошла (TCP → SOCKS5 → CONNECT во внешний
/// мир). Пока проверка не прошла, настройки Windows не трогаются вообще, поэтому первый же
/// пакет браузера уходит в работающий туннель, а не в пустоту.
/// </summary>
internal static class ProxySession
{
    private static string _phoneHost = string.Empty;
    private static int _port;
    private static bool _running;
    private static readonly List<string> _log = [];
    private static readonly Lock _sync = new();
    private static int _proxyOwned;      // 1 = системный прокси включили мы
    private static int _ttlOwned;        // 1 = TTL=65 поставили мы и должны откатить
    private static int _envOwned;        // 1 = переменные окружения прокси поставили мы
    private static int _envSuspended;    // 1 = переменные временно сняты (телефон недоступен)
    private static int _cleanedUp;
    private static Timer? _watchdog;
    private static int _misses;
    private static int _recovering;

    public static event EventHandler? Changed;

    /// <summary>Переподключаться автоматически, если связь с телефоном пропала.</summary>
    public static bool AutoReconnect { get; set; } = true;

    /// <summary>Прокси включён, но телефон сейчас не отвечает (идёт восстановление).</summary>
    public static bool LinkLost { get; private set; }

    public static bool IsRunning => _running;

    /// <summary>Адрес прокси — ровно то, что попадает в настройки Windows.</summary>
    public static string EndpointHost => _phoneHost;

    public static int Port => _port;

    public static string LogText
    {
        get
        {
            lock (_sync) return string.Join("\n", _log.TakeLast(120));
        }
    }

    /// <summary>
    /// Подключение к точке доступа телефона.
    /// Возвращает (ok, сообщение). Пока ok = false, системный прокси не изменён ни на байт.
    /// </summary>
    public static async Task<(bool Ok, string Message)> StartAsync(
        int port,
        string phoneHost,
        bool setSystemProxy,
        bool setEnvironmentProxy = true,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        if (_running) return (true, "Уже подключено");

        // Ждём, пока канал реально заработает: телефон мог ещё поднимать точку доступа
        // или приложение на нём ещё не нажало кольцо.
        //
        // Главная хитрость: адрес телефона НЕ фиксирован. Samsung при подключении клиента
        // к точке доступа может сменить и подсеть, и адрес (у вас это 10.185.189.x),
        // а старый адрес из поля ввода остаётся в приложении навсегда. Поэтому во время
        // ожидания мы каждый раз заново ищем актуальный адрес и пробуем именно его —
        // иначе приходится нажимать «Подключить» по десять раз.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(45);
        var ready = false;
        var lastMessage = "Телефон не отвечает";
        var attempt = 0;
        var host = string.Empty;

        // Кандидаты на проверку: сначала то, что ввёл пользователь, потом — найденные сами.
        var candidates = new List<string>();

        void AddCandidate(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            var trimmed = value.Trim();
            if (!IPAddress.TryParse(trimmed, out var ip)) return;
            if (ip.Equals(IPAddress.Any) || IPAddress.IsLoopback(ip)) return;
            if (!candidates.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
                candidates.Add(trimmed);
        }

        AddCandidate(phoneHost);
        AddCandidate(GatewayProbe.DetectPhoneAddress());

        while (true)
        {
            attempt++;

            // На каждой попытке узнаём актуальный адрес телефона заново: подсеть могла смениться.
            AddCandidate(GatewayProbe.DetectPhoneAddress());

            host = candidates.Count > 0 ? candidates[0] : string.Empty;

            if (!string.IsNullOrWhiteSpace(host))
            {
                try
                {
                    var (ok, message) = await ProxyProbe
                        .CheckEndToEndAsync(host, port, ct)
                        .ConfigureAwait(false);

                    lastMessage = message;

                    if (ok)
                    {
                        ready = true;
                        break;
                    }
                }
                catch (OperationCanceledException)
                {
                    AppendLog("Подключение отменено");
                    return (false, "Подключение отменено");
                }
            }
            else
            {
                lastMessage = "Не найден IP телефона — подключитесь к его точке доступа";
            }

            // Шлюз может указывать не туда (ноутбук ещё переподключается к сети телефона),
            // а адрес телефона — уже новый. Тогда ищем прокси перебором по подсети.
            if (attempt == 2 || (attempt > 2 && attempt % 3 == 0))
            {
                progress?.Report("Ищу телефон в сети…");

                try
                {
                    var found = await GatewayProbe.ScanSubnetForProxyAsync(port, ct).ConfigureAwait(false);
                    if (found is not null && !string.Equals(found, host, StringComparison.OrdinalIgnoreCase))
                    {
                        AppendLog($"Телефон найден в сети: {found} (вместо {host})");
                        candidates.Clear();
                        AddCandidate(found);
                        host = found;
                    }
                }
                catch (OperationCanceledException)
                {
                    AppendLog("Подключение отменено");
                    return (false, "Подключение отменено");
                }
            }

            progress?.Report($"{lastMessage} · попытка {attempt}");

            if (DateTime.UtcNow >= deadline) break;

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1.5), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                AppendLog("Подключение отменено");
                return (false, "Подключение отменено");
            }
        }

        if (!ready)
        {
            AppendLog($"Канал не готов: {lastMessage}");
            return (false, lastMessage);
        }

        // Проверяем стелс-маскировку: если недоступна, просто логируем предупреждение.
        // Подключение продолжается, но оператор может обнаружить трафик ноутбука.
        if (!CarrierStealthFilter.VerifyStealthEnvironment())
        {
            AppendLog("Предупреждение: стелс-маскировка недоступна (требует прав администратора).");
        }

        // Вот здесь и только здесь — момент, когда можно отдавать трафик в туннель.
        _phoneHost = host;
        _port = port;
        _running = true;
        LinkLost = false;
        AppendLog($"Канал проверен: {lastMessage}");

        if (setSystemProxy)
        {
            try
            {
                var server = ProxyFormat.BuildServerString(host, port);
                WindowsProxy.Enable(server);
                WindowsProxy.SaveOwned(server, null);
                Interlocked.Exchange(ref _proxyOwned, 1);
                AppendLog($"Системный прокси Windows включён на {host}:{port}");

                // Активируем защиту от обнаружения оператором (TTL = 65)
                // Требует запуска приложения от имени Администратора!
                if (WindowsTtlProtector.EnableCarrierStealthTtl())
                {
                    Interlocked.Exchange(ref _ttlOwned, 1);
                    AppendLog("Защита от раздачи (TTL = 65) успешно активирована");
                }
                else
                {
                    AppendLog("Предупреждение: не удалось установить TTL = 65 (запустите приложение от Администратора)");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Системный прокси не изменён: {ex.Message}");
            }
        }

        // Переменные окружения — для приложений, которые не читают системный прокси
        // Windows: opencode (Bun), git, npm, docker, pip. Без них они идут мимо туннеля.
        if (setEnvironmentProxy)
        {
            try
            {
                ProxyEnvironment.Apply(host, port);
                Interlocked.Exchange(ref _envOwned, 1);
                AppendLog($"Переменные прокси заданы: HTTP_PROXY/HTTPS_PROXY = http://{host}:{port}");
                AppendLog("Внимание: новые терминалы и opencode подхватят их сразу; уже открытые — после перезапуска");

                // Если opencode уже запущен — прямо говорим, что надо перезапустить,
                // иначе пользователь будет долго гадать, почему DeepSeek не отвечает.
                if (System.Diagnostics.Process.GetProcessesByName("opencode").Length > 0)
                {
                    AppendLog("⚠ OpenCode сейчас запущен и НЕ увидит новые переменные — перезапустите его, чтобы DeepSeek пошёл через телефон");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Переменные окружения не заданы: {ex.Message}");
            }
        }

        StartWatchdog(port);
        AppendLog($"Подключено через точку доступа {host}:{port}");
        RaiseChanged();

        return (true, $"Подключено: {host}:{port}");
    }

    /// <summary>
    /// Проверка «есть ли смысл пробовать»: живое SOCKS5-рукопожатие без выхода в интернет.
    /// Используется кнопкой «Проверить» в интерфейсе.
    /// </summary>
    public static Task<(bool Ok, string Message)> ProbeProxyAsync(string host, int port)
        => ProxyProbe.CheckAsync(host, port);

    /// <summary>
    /// Если прошлый запуск завершился аварийно (kill), системный прокси мог остаться включённым.
    /// Проверяем: живёт ли за ним туннель на телефоне, если нет — выключаем.
    /// Важно: прокси-сервер НЕ локальный — он живёт на телефоне в точке доступа.
    /// Поэтому IsPortListening(localPort) не работает; нужна TCP-попытка к адресу телефона.
    /// </summary>
    public static void HealStaleState()
    {
        try
        {
            if (!WindowsProxy.IsOursActive()) return;

            var host = WindowsProxy.ServerHost;
            var port = WindowsProxy.ServerPort;

            if (port > 0 && !string.IsNullOrWhiteSpace(host) && IsReachable(host, port))
            {
                // Прокси живой — восстанавливаем рабочее состояние без лишнего подключения.
                // Регистрируем хост/порт в сессии, запускаем watchdog, пользователю ничего делать не надо.
                _phoneHost = host;
                _port = port;
                _running = true;
                Interlocked.Exchange(ref _proxyOwned, 1);
                StartWatchdog(port);
                AppendLog($"Восстановлено: прокси {host}:{port} уже работает");

                // Переменные окружения тоже могли остаться с прошлого раза —
                // восстанавливаем их, чтобы адрес соответствовал текущей точке доступа.
                try
                {
                    ProxyEnvironment.Apply(host, port);
                    Interlocked.Exchange(ref _envOwned, 1);
                    AppendLog($"Переменные прокси восстановлены: http://{host}:{port}");
                }
                catch (Exception ex)
                {
                    AppendLog($"Переменные окружения не восстановлены: {ex.Message}");
                }
                return;
            }

            // Прокси не отвечает — убираем зависший реестр.
            WindowsProxy.Disable();
            WindowsProxy.ClearOwned();
            AppendLog($"Найден «висящий» прокси от прошлого запуска ({host}:{port}) — выключен");
        }
        catch (Exception ex)
        {
            AppendLog($"Проверка прошлого запуска: {ex.Message}");
        }
    }

    private static void StartWatchdog(int port)
    {
        StopWatchdog();
        Interlocked.Exchange(ref _misses, 0);
        _watchdog = new Timer(_ => WatchdogTick(port), null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
    }

    private static void StopWatchdog()
    {
        var timer = _watchdog;
        _watchdog = null;
        timer?.Dispose();
    }

    /// <summary>
    /// Телефон ушёл в сон, точка доступа перезагрузилась, Wi-Fi моргнул.
    /// Связь помечаем потерянной, системный прокси не снимаем: как только телефон
    /// вернётся, всё заработает само.
    ///
    /// ВАЖНО: если ноутбук ушёл в другую сеть (например на домашний Wi-Fi),
    /// переменные HTTP_PROXY продолжают указывать на недостижимый адрес телефона.
    /// Тогда opencode/git/npm бесконечно пытаются подключиться к пустоте.
    /// Поэтому при длительной потере связи переменные окружения снимаем,
    /// а при восстановлении — ставим заново, с актуальным адресом.
    /// </summary>
    private static void WatchdogTick(int port)
    {
        if (!_running) return;

        if (IsReachable(_phoneHost, port))
        {
            Interlocked.Exchange(ref _misses, 0);

            if (LinkLost)
            {
                LinkLost = false;
                AppendLog("Связь с телефоном восстановлена");
                RaiseChanged();
            }

            return;
        }

        var misses = Interlocked.Increment(ref _misses);
        if (misses < 2) return;

        Interlocked.Exchange(ref _misses, 0);

        if (!LinkLost)
        {
            LinkLost = true;
            AppendLog("Связь с телефоном пропала — восстанавливаю…");
            RaiseChanged();
        }

        // 6 пропусков подряд (18 секунд) — телефон недоступен. Снимаем переменные
        // окружения: они сейчас уводят opencode и прочие инструменты в пустоту.
        if (misses >= 6)
        {
            SuspendEnvironmentProxy();
        }

        if (AutoReconnect) _ = RecoverAsync(port);
    }

    /// <summary>
    /// Временно снимает переменные прокси, пока телефон недоступен.
    /// Системный прокси Windows при этом остаётся: браузеры покажут нормальную
    /// страницу ошибки, а не зависнут.
    /// </summary>
    private static void SuspendEnvironmentProxy()
    {
        if (Interlocked.Exchange(ref _envSuspended, 0) == 1) return;

        try
        {
            ProxyEnvironment.Restore();
            AppendLog("Переменные прокси сняты: телефон недоступен — opencode и git не будут стучаться в пустоту");
        }
        catch (Exception ex)
        {
            AppendLog($"Не удалось снять переменные прокси: {ex.Message}");
        }

        Interlocked.Exchange(ref _envSuspended, 1);
    }

    /// <summary>
    /// Возвращает переменные прокси с актуальным адресом телефона.
    /// </summary>
    private static void ResumeEnvironmentProxy()
    {
        if (Interlocked.Exchange(ref _envSuspended, 0) == 0) return;
        if (string.IsNullOrWhiteSpace(_phoneHost) || _port <= 0) return;

        try
        {
            ProxyEnvironment.Apply(_phoneHost, _port);
            Interlocked.Exchange(ref _envOwned, 1);
            AppendLog($"Переменные прокси возвращены: http://{_phoneHost}:{_port}");
        }
        catch (Exception ex)
        {
            AppendLog($"Не удалось вернуть переменные прокси: {ex.Message}");
        }
    }

    /// <summary>Пробуем вернуть канал: телефон мог получить новый адрес,
    /// переподключиться к Wi-Fi или подняться заново. Перебираем старые адреса,
    /// ищем шлюз Wi-Fi заново и, если надо, сканируем подсеть.</summary>
    private static async Task RecoverAsync(int port)
    {
        if (Interlocked.Exchange(ref _recovering, 1) == 1) return;

        try
        {
            var attemptsTotal = 6;
            var scanTriggered = false;

            for (var attempt = 1; attempt <= attemptsTotal && _running; attempt++)
            {
                // 1) Пробуем старые адреса: телефон мог вернуться на тот же IP.
                if (IsReachable(_phoneHost, port))
                {
                    LinkLostAfterRecovery();
                    return;
                }

                // 2) Ищем шлюз Wi-Fi заново: Samsung часто меняет подсеть/адрес при
                //    переподключении точки доступа, и старый IP уже не валиден.
                var gateway = GatewayProbe.DetectPhoneAddress();
                if (!string.IsNullOrWhiteSpace(gateway) &&
                    !string.Equals(gateway, _phoneHost, StringComparison.OrdinalIgnoreCase) &&
                    IsReachable(gateway, port))
                {
                    AppendLog($"Телефон теперь отвечает по {gateway} (было {_phoneHost})");
                    _phoneHost = gateway;
                    ApplyEnvironmentProxyIfOwned(gateway, port);
                    LinkLostAfterRecovery();
                    return;
                }

                // 3) На второй и четвёртой попытке — скан подсети, на случай если
                //    шлюз ещё не переключился или DHCP на ноутбуке ещё не обновился.
                if (!scanTriggered && attempt >= 2)
                {
                    scanTriggered = true;
                    try
                    {
                        var found = await GatewayProbe
                            .ScanSubnetForProxyAsync(port)
                            .ConfigureAwait(false);

                        if (found is not null && IsReachable(found, port))
                        {
                            AppendLog($"Телефон найден в сети: {found}");
                            _phoneHost = found;
                            ApplyEnvironmentProxyIfOwned(found, port);
                            LinkLostAfterRecovery();
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        AppendLog($"Скан подсети не удался: {ex.Message}");
                    }
                }

                if (attempt < attemptsTotal)
                    await Task.Delay(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            }

            AppendLog("Связь не вернулась — проверьте точку доступа и приложение на телефоне");
        }
        catch (Exception ex)
        {
            AppendLog($"Переподключение не удалось: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _recovering, 0);
        }
    }

    private static void LinkLostAfterRecovery()
    {
        LinkLost = false;
        ResumeEnvironmentProxy();
        AppendLog("Соединение восстановлено");
        RaiseChanged();
    }

    /// <summary>
    /// Обновляет переменные окружения с новым адресом телефона, если мы их ставили.
    /// </summary>
    private static void ApplyEnvironmentProxyIfOwned(string host, int port)
    {
        if (Interlocked.Exchange(ref _envOwned, 0) == 0) return;

        try
        {
            ProxyEnvironment.Apply(host, port);
            Interlocked.Exchange(ref _envOwned, 1);
            Interlocked.Exchange(ref _envSuspended, 0);
            AppendLog($"Переменные прокси обновлены: http://{host}:{port}");
        }
        catch (Exception ex)
        {
            AppendLog($"Не удалось обновить переменные прокси: {ex.Message}");
        }
    }

    private static bool IsReachable(string host, int port)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;

        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(TimeSpan.FromMilliseconds(1500)) && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Полный откат: системный прокси снимается, TTL восстанавливается, состояние сбрасывается.</summary>
    public static Task StopAsync()
    {
        _running = false;
        _phoneHost = string.Empty;
        _port = 0;
        LinkLost = false;
        StopWatchdog();

        ReleaseSystemProxy();
        RestoreEnvironmentProxy();
        RestoreTtl();

        AppendLog("Отключено: настройки Windows восстановлены");
        RaiseChanged();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Синхронная аварийная уборка на выходе из приложения (закрытие окна, выгрузка процесса).
    /// </summary>
    public static void CleanupBlocking()
    {
        if (Interlocked.Exchange(ref _cleanedUp, 1) == 1) return;

        _running = false;
        _phoneHost = string.Empty;
        _port = 0;
        LinkLost = false;
        StopWatchdog();

        ReleaseSystemProxy();
        RestoreEnvironmentProxy();
        RestoreTtl();
    }

    /// <summary>Выключаем прокси только если включали его мы.</summary>
    private static void ReleaseSystemProxy()
    {
        try
        {
            var owned = Interlocked.Exchange(ref _proxyOwned, 0) == 1;
            if (owned || WindowsProxy.IsOursActive())
            {
                WindowsProxy.Disable();
                WindowsProxy.ClearOwned();
                AppendLog("Системный прокси Windows выключен");
            }
        }
        catch (Exception ex)
        {
            AppendLog($"Не удалось выключить системный прокси: {ex.Message}");
        }
    }

    /// <summary>Возвращаем переменные окружения к состоянию до подключения.</summary>
    private static void RestoreEnvironmentProxy()
    {
        if (Interlocked.Exchange(ref _envOwned, 0) == 0) return;

        try
        {
            ProxyEnvironment.Restore();
            AppendLog("Переменные HTTP_PROXY/HTTPS_PROXY восстановлены");
        }
        catch (Exception ex)
        {
            AppendLog($"Не удалось восстановить переменные прокси: {ex.Message}");
        }
    }

    /// <summary>Откатываем TTL обратно в 128 (Windows default), только если TTL ставили мы.</summary>
    private static void RestoreTtl()
    {
        if (Interlocked.Exchange(ref _ttlOwned, 0) == 1)
        {
            if (WindowsTtlProtector.RestoreDefaultTtl())
                AppendLog("TTL восстановлен (128)");
        }
    }

    public static void AppendLog(string message)
    {
        lock (_sync)
        {
            _log.Add($"{DateTime.Now:HH:mm:ss}  {message}");
            if (_log.Count > 300) _log.RemoveRange(0, _log.Count - 300);
        }

        RaiseChanged();
    }

    private static void RaiseChanged()
    {
        try
        {
            Changed?.Invoke(null, EventArgs.Empty);
        }
        catch
        {
            // обработчики интерфейса не должны ронять сессию
        }
    }
}
