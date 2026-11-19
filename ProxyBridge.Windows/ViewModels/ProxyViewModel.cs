#pragma warning disable MVVMTK0045 // WinUI: используем поля [ObservableProperty]
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProxyBridge.Windows.Services;

namespace ProxyBridge.Windows.ViewModels;

/// <summary>
/// Модель окна ноутбука. Функционал только «компьютерный»: одно кольцо-выключатель,
/// один режим — телефон в режиме точки доступа. Системный прокси включается
/// строго после сквозной проверки канала, поэтому первый пакет всегда уходит по адресу.
/// </summary>
public partial class ProxyViewModel : ObservableObject
{
    private static readonly Color OkColor = Color.FromArgb("#5FB3D4");
    private static readonly Color WarnColor = Color.FromArgb("#C9A65F");
    private static readonly Color IdleColor = Color.FromArgb("#7E8B96");
    private static readonly Color IdleStroke = Color.FromArgb("#232B33");

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _detailText = "Нажмите кольцо, чтобы подключиться";

    [ObservableProperty]
    private string _portText = "9000";

    [ObservableProperty]
    private bool _setSystemProxy = true;

    [ObservableProperty]
    private bool _setEnvironmentProxy = true;

    [ObservableProperty]
    private bool _closeOpencodeSession = true;

    [ObservableProperty]
    private bool _autoReconnect = true;

    [ObservableProperty]
    private string _phoneIp = "192.168.43.1";

    [ObservableProperty]
    private string _logText = string.Empty;

    [ObservableProperty]
    private string _checkResultText = string.Empty;

    [ObservableProperty]
    private string _powerText = "Отключено";

    [ObservableProperty]
    private string _powerSubText = "нажмите, чтобы подключиться";

    [ObservableProperty]
    private Color _powerTextColor = IdleColor;

    [ObservableProperty]
    private double _powerGlowOpacity;

    [ObservableProperty]
    private Brush _powerStroke = new SolidColorBrush(IdleStroke);

    // Последний результат действия: Refresh() не должен его затирать,
    // иначе причина отказа исчезает через мгновение после нажатия.
    private string? _lastActionMessage;
    private bool _lastActionFailed;
    private DateTime _lastActionAt = DateTime.MinValue;

    private CancellationTokenSource? _connectCts;
    private IDispatcherTimer? _uiTimer;

    private readonly DateTime _startedAt = DateTime.UtcNow;
    private bool _userEditedIp;
    private bool _suppressIpEdit;
    private DateTime _lastIpProbe = DateTime.MinValue;

    public ProxyViewModel()
    {
        ProxySession.AutoReconnect = AutoReconnect;
        OpencodeSession.Enabled = CloseOpencodeSession;
        ProxySession.HealStaleState();
        ProxySession.Changed += (_, _) => Refresh();
        Refresh();
        StartUiTimer();
    }

    /// <summary>
    /// Раз в секунду обновляем состояние: связь может пропасть и восстановиться сама,
    /// и интерфейс должен это показывать без нажатий.
    /// </summary>
    private void StartUiTimer()
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null) return;

        _uiTimer = dispatcher.CreateTimer();
        _uiTimer.Interval = TimeSpan.FromSeconds(1);
        _uiTimer.Tick += (_, _) => Refresh();
        _uiTimer.Start();
    }

    /// <summary>Найденный адрес телефона показываем сразу: видно, куда пойдёт подключение.</summary>
    public string Endpoint => IsRunning
        ? $"{ProxySession.EndpointHost}:{ProxySession.Port}"
        : string.IsNullOrWhiteSpace(PhoneIp) ? "—" : $"{PhoneIp}:{PortText}";

    public string ModeName => IsRunning ? "точка доступа" : IsBusy ? "проверка" : "ожидание";

    private int Port => int.TryParse(PortText, out var p) && p is > 0 and < 65536 ? p : 9000;

    partial void OnAutoReconnectChanged(bool value) => ProxySession.AutoReconnect = value;

    partial void OnCloseOpencodeSessionChanged(bool value) => OpencodeSession.Enabled = value;

    partial void OnPortTextChanged(string value) => OnPropertyChanged(nameof(Endpoint));

    partial void OnPhoneIpChanged(string value)
    {
        // Ручной ввод важнее автопоиска — но ⟳ снова включает автопоиск.
        // Первые секунды после старта не считаем правкой: так значение приходит из привязки.
        if (!_suppressIpEdit && DateTime.UtcNow - _startedAt > TimeSpan.FromSeconds(3))
            _userEditedIp = true;
        OnPropertyChanged(nameof(Endpoint));
    }

    /// <summary>
    /// Телефон в точке доступа — это шлюз Wi-Fi, поэтому адрес находится сам.
    /// Подсеть Samsung нельзя угадать (10.240.x.x), а ручной ввод — лишний шаг.
    /// </summary>
    private void ApplyDetectedIp()
    {
        // Ручной ввод уважаем, но только если это НЕ заводской дефолт:
        // у Samsung подсеть точки доступа случайная (10.185.x.x), и дефолт не работает.
        if (_userEditedIp && !IsDefaultPhoneIp) return;
        if (DateTime.UtcNow - _lastIpProbe < TimeSpan.FromSeconds(5)) return;

        _lastIpProbe = DateTime.UtcNow;

        var detected = GatewayProbe.DetectPhoneAddress();
        if (detected is null || string.Equals(PhoneIp, detected, StringComparison.Ordinal)) return;

        _suppressIpEdit = true;
        PhoneIp = detected;
        _suppressIpEdit = false;

        // Найденный адрес рабочий — дальше переопределять его вручную незачем.
        _userEditedIp = false;
    }

    /// <summary>Адрес в поле совпадает с заводским дефолтом (у Samsung он не подходит).</summary>
    private bool IsDefaultPhoneIp =>
        string.IsNullOrWhiteSpace(PhoneIp) ||
        PhoneIp.Trim() is "192.168.43.1" or "192.168.42.129" or "192.168.49.1";

    private void SetPhoneIp(string value)
    {
        _suppressIpEdit = true;
        PhoneIp = value;
        _suppressIpEdit = false;
        _userEditedIp = false;
    }

    /// <summary>
    /// Одно нажатие на кольцо: выключено — подключаемся, включено — отключаемся,
    /// идёт проверка — нажатие отменяет ожидание.
    /// </summary>
    [RelayCommand]
    private async Task ToggleAsync()
    {
        if (IsBusy)
        {
            _connectCts?.Cancel();
            return;
        }

        if (ProxySession.IsRunning)
            await StopAsync();
        else
            await StartAsync();
    }

    [RelayCommand]
    private async Task StartAsync()
    {
        if (IsBusy || ProxySession.IsRunning) return;

        if (!int.TryParse(PortText, out var port) || port is < 1 or > 65535)
        {
            RememberAction(false, "Порт должен быть 1..65535");
            Refresh();
            return;
        }

        IsBusy = true;
        _connectCts = new CancellationTokenSource();
        DetailText = "Проверяю канал до телефона…";
        Refresh();

        var progress = new Progress<string>(message =>
        {
            DetailText = message;
            PowerSubText = message;
        });

        try
        {
            var (ok, message) = await ProxySession.StartAsync(
                port, PhoneIp.Trim(), SetSystemProxy, SetEnvironmentProxy, progress, _connectCts.Token);

            // Адрес мог смениться прямо во время подключения — показываем тот, который реально работает.
            if (ok && !string.IsNullOrWhiteSpace(ProxySession.EndpointHost))
                SetPhoneIp(ProxySession.EndpointHost);

            RememberAction(ok, message);
            DetailText = message;
        }
        catch (OperationCanceledException)
        {
            DetailText = "Подключение отменено";
        }
        catch (Exception ex)
        {
            RememberAction(false, $"Не удалось подключиться: {ex.Message}");
            DetailText = _lastActionMessage ?? "Не удалось подключиться";
        }
        finally
        {
            _connectCts?.Dispose();
            _connectCts = null;
            IsBusy = false;
            Refresh();
        }
    }

    /// <summary>Запоминает сообщение действия, чтобы оно пережило следующий Refresh.</summary>
    private void RememberAction(bool ok, string? message)
    {
        _lastActionMessage = message;
        _lastActionFailed = !ok;
        _lastActionAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Проверка канала вручную: та же сквозная проверка, что и при подключении,
    /// поэтому её вердикт совпадает с тем, что увидит браузер.
    /// </summary>
    [RelayCommand]
    private async Task CheckPhoneAsync()
    {
        CheckResultText = "Проверяю…";

        var host = ProxySession.IsRunning ? ProxySession.EndpointHost : PhoneIp.Trim();
        var (ok, message) = await ProxyBridge.Core.ProxyProbe.CheckEndToEndAsync(host, Port);

        CheckResultText = message;
        RememberAction(ok, message);
        ProxySession.AppendLog(message);
        DetailText = message;
        Refresh();
    }

    [RelayCommand]
    private async Task StopAsync()
    {
        _connectCts?.Cancel();
        await ProxySession.StopAsync();
        Refresh();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        // ⟳ — заново найти телефон в сети, даже если адрес правили руками.
        _lastIpProbe = DateTime.MinValue;
        _userEditedIp = false;

        var detected = GatewayProbe.DetectPhoneAddress();
        if (detected is not null) SetPhoneIp(detected);

        Refresh();
        await Task.CompletedTask;
    }

    /// <summary>
    /// «Красная кнопка» — полный сброс сети к стандарту. Убирает всё, что могло
    /// «поломать интернет» после раздачи: системный прокси, переменные окружения
    /// (даже от прошлых сессий), PAC, TTL, DNS-кэш.
    /// </summary>
    [RelayCommand]
    private async Task ResetNetworkAsync()
    {
        if (IsBusy) return;

        IsBusy = true;
        PowerText = "Сброс";
        PowerSubText = "возвращаю стандартные настройки…";
        DetailText = "Сбрасываю сетевые настройки к стандартным…";
        Refresh();

        try
        {
            var report = await Task.Run(ProxySession.ResetNetworkToDefaults);

            RememberAction(true, "Сеть сброшена к стандарту. Перезапустите opencode и терминалы, если они были открыты.");
            DetailText = $"Сброс выполнен: {report}. Перезапустите opencode, если он был открыт.";
        }
        catch (Exception ex)
        {
            RememberAction(false, $"Сброс не удался: {ex.Message}");
            DetailText = _lastActionMessage ?? "Сброс не удался";
        }
        finally
        {
            IsBusy = false;
            Refresh();
        }
    }

    /// <summary>
    /// Открывает список сетей Wi-Fi: чаще всего ноутбук просто ушёл на домашнюю
    /// сеть, и нужно переключиться обратно на точку доступа телефона.
    /// </summary>
    [RelayCommand]
    private async Task OpenWifiSettingsAsync()
    {
        try
        {
            await Launcher.Default.OpenAsync("ms-settings:network-wifi");
            DetailText = "Выберите точку доступа телефона в списке Wi-Fi";
        }
        catch (Exception ex)
        {
            DetailText = $"Не удалось открыть настройки Wi-Fi: {ex.Message}";
        }
    }

    public void Refresh()
    {
        if (!MainThread.IsMainThread)
        {
            MainThread.BeginInvokeOnMainThread(Refresh);
            return;
        }

        IsRunning = ProxySession.IsRunning;
        LogText = ProxySession.LogText;

        if (IsRunning)
        {
            PortText = ProxySession.Port.ToString();

            // Синхронизируем поле IP с реально используемым адресом телефона:
            // иначе после автовосстановления (HealStaleState) там останется старое
            // 192.168.43.1, и повторное подключение уйдёт в пустоту.
            var activeHost = ProxySession.EndpointHost;
            if (!string.IsNullOrWhiteSpace(activeHost) &&
                !string.Equals(PhoneIp, activeHost, StringComparison.Ordinal))
            {
                SetPhoneIp(activeHost);
            }

            var linkLost = ProxySession.LinkLost;
            PowerText = linkLost ? "Нет связи" : "Подключено";
            PowerSubText = linkLost ? "восстанавливаю…" : "нажмите, чтобы отключить";
            PowerStroke = new SolidColorBrush(linkLost ? WarnColor : OkColor);
            PowerTextColor = linkLost ? WarnColor : OkColor;
            PowerGlowOpacity = linkLost ? 0.18 : 0.7;

            // При потере связи самое полезное — сказать, что делать:
            // скорее всего, ноутбук ушёл в другую сеть (домашний Wi-Fi).
            DetailText = linkLost
                ? "Телефон недоступен — подключитесь к его точке доступа"
                : $"Через точку доступа {ProxySession.EndpointHost}:{ProxySession.Port}";
        }
        else
        {
            PowerText = IsBusy ? "Проверяю" : "Отключено";
            PowerSubText = IsBusy ? "жду телефон…" : "нажмите, чтобы подключиться";
            PowerStroke = new SolidColorBrush(IsBusy ? WarnColor : IdleStroke);
            PowerTextColor = IsBusy ? WarnColor : IdleColor;
            PowerGlowOpacity = IsBusy ? 0.25 : 0;

            // Недавняя неудача важнее общей подсказки: показываем её ещё 20 секунд.
            if (_lastActionFailed && _lastActionMessage is not null &&
                DateTime.UtcNow - _lastActionAt < TimeSpan.FromSeconds(20))
            {
                DetailText = _lastActionMessage;
            }
            else if (!IsBusy)
            {
                ApplyDetectedIp();

                // Если телефон есть в сети, но прокси на нём не отвечает —
                // предупреждаем прямо, а не даём копить попытки.
                DetailText = _lastActionFailed && _lastActionMessage is not null &&
                             DateTime.UtcNow - _lastActionAt < TimeSpan.FromSeconds(20)
                    ? _lastActionMessage
                    : "Нажмите кольцо, чтобы подключиться";
            }
        }

        OnPropertyChanged(nameof(Endpoint));
        OnPropertyChanged(nameof(ModeName));
    }
}
