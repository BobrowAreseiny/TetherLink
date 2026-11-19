using Android.Content;
using Android.OS;
using Android.Provider;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProxyBridge.Android.Services;

namespace ProxyBridge.Android.ViewModels;

/// <summary>
/// Модель телефона. Режим один — точка доступа: телефон раздаёт Wi-Fi и слушает прокси
/// на адресе этой точки, ноутбук подключается по нему. USB-режима нет.
/// </summary>
public partial class ProxyViewModel : ObservableObject
{
    private static readonly Color RunningColor = Color.FromArgb("#5FB3D4");
    private static readonly Color WarnColor = Color.FromArgb("#C9A65F");
    private static readonly Color IdleColor = Color.FromArgb("#7E8B96");
    private static readonly Color IdleStroke = Color.FromArgb("#232B33");

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private string _statusText = "Выключено";

    [ObservableProperty]
    private string _detailText = "Нажмите кольцо, чтобы включить";

    [ObservableProperty]
    private string _ipAddress = "—";

    [ObservableProperty]
    private string _portText = "9000";

    [ObservableProperty]
    private string _trafficUp = "↑ 0 Б";

    [ObservableProperty]
    private string _trafficDown = "↓ 0 Б";

    [ObservableProperty]
    private string _speedUp = "↑ 0 Б/с";

    [ObservableProperty]
    private string _speedDown = "↓ 0 Б/с";

    [ObservableProperty]
    private string _activeConnections = "0";

    [ObservableProperty]
    private string _logText = string.Empty;

    // Кольцо: текст и цвет внутри зависят только от состояния сервера.
    [ObservableProperty]
    private string _powerText = "Выключено";

    [ObservableProperty]
    private string _powerSubText = "нажмите, чтобы включить";

    [ObservableProperty]
    private Color _powerTextColor = IdleColor;

    [ObservableProperty]
    private double _powerGlowOpacity;

    [ObservableProperty]
    private Brush _powerStroke = new SolidColorBrush(IdleStroke);

    private bool _busy;
    private IDispatcherTimer? _uiTimer;

    // Последний результат действия: таймер обновления не должен затирать ошибку
    // через секунду после нажатия — иначе причина отказа не читается.
    private string? _lastMessage;
    private bool _lastFailed;
    private DateTime _lastAt = DateTime.MinValue;

    // Для расчёта скорости: разница байт между тиками таймера.
    private DateTime _lastStatsAt = DateTime.MinValue;
    private long _lastStatsUp;
    private long _lastStatsDown;

    private void Remember(bool ok, string message)
    {
        _lastMessage = message;
        _lastFailed = !ok;
        _lastAt = DateTime.UtcNow;
    }

    /// <summary>Адрес для ноутбука: IP в точке доступа и порт.</summary>
    public string ClientAddress => IsRunning
        ? $"{ProxyForegroundService.AdvertisedHost}:{ProxyForegroundService.ActivePort}"
        : "—";

    partial void OnIsRunningChanged(bool value)
    {
        OnPropertyChanged(nameof(ClientAddress));
    }

    private int Port => int.TryParse(PortText, out var p) && p is > 0 and < 65536 ? p : 9000;

    /// <summary>Проверяет, не оптимизирует ли система батарею для приложения.
    /// Samsung/One UI в режиме энергосбережения убивает фоновые сокеты и сервис,
    /// от чего ноутбук получает "Network is unreachable" через пару минут.</summary>
    private void EnsureBatteryOptimizationExemption()
    {
        try
        {
            var context = global::Microsoft.Maui.ApplicationModel.Platform.AppContext;
            var pm = (PowerManager?)context.GetSystemService(Context.PowerService);
            if (pm is null) return;

            var pkg = context.PackageName;
            if (pm.IsIgnoringBatteryOptimizations(pkg)) return;

            // Только один раз за сессию — иначе каждое нажатие кольца открывает настройки.
            if (_batteryHintShown) return;
            _batteryHintShown = true;

            // Мягкое предупреждение: пользователь сам решит, открывать ли настройки.
            var intent = new Intent(Settings.ActionRequestIgnoreBatteryOptimizations);
            intent.SetData(global::Android.Net.Uri.Parse("package:" + pkg));
            intent.AddFlags(ActivityFlags.NewTask);
            context.StartActivity(intent);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] battery optimization hint: {ex.Message}");
        }
    }

    private bool _batteryHintShown;

    /// <summary>Одно нажатие на кольцо — включить или выключить прокси.</summary>
    [RelayCommand]
    private async Task ToggleAsync()
    {
        if (_busy) return;

        _busy = true;
        try
        {
            if (ProxyForegroundService.IsRunning)
                await StopAsync();
            else
                await StartAsync();
        }
        finally
        {
            _busy = false;
            Refresh();
        }
    }

    [RelayCommand]
    private async Task StartAsync()
    {
        if (!int.TryParse(PortText, out var port) || port is < 1 or > 65535)
        {
            StatusText = "Выключено";
            DetailText = "Порт должен быть 1..65535";
            return;
        }

        // На Samsung/One UI режим энергосбережения убивает фоновый сервис и обрывает
        // TCP-соединение через несколько минут. Один раз за сессию предлагаем
        // пользователю исключить приложение из оптимизации батареи.
        EnsureBatteryOptimizationExemption();

        var context = global::Microsoft.Maui.ApplicationModel.Platform.AppContext;

        // Сначала проверяем точку доступа: без неё ноутбуку некуда подключаться,
        // поэтому прокси не поднимаем вообще.
        var address = HotspotIpResolver.ResolveAdvertisedAddress(context);
        if (address is null)
        {
            const string noHotspot = "Точка доступа не найдена — включите её и нажмите кольцо снова";
            Remember(false, noHotspot);
            StatusText = "Выключено";
            DetailText = noHotspot;
            IpAddress = "—";
            return;
        }

        IpAddress = address.ToString();
        StatusText = "Включаю…";
        DetailText = $"Прокси будет доступен по {address}:{port}";

        await EnsureNotificationPermissionAsync();

        var intent = new Intent(context, typeof(ProxyForegroundService));
        intent.SetAction(ProxyForegroundService.ActionStart);
        intent.PutExtra(ProxyForegroundService.ExtraPort, port);

        if (OperatingSystem.IsAndroidVersionAtLeast(26))
            context.StartForegroundService(intent);
        else
            context.StartService(intent);

        await Task.Delay(900);
        Refresh();

        if (!IsRunning)
        {
            var reason = string.IsNullOrEmpty(ProxyForegroundService.LastError)
                ? $"Порт {port} занят — попробуйте другой"
                : ProxyForegroundService.LastError;

            Remember(false, reason);
            StatusText = "Выключено";
            DetailText = reason;
        }
    }

    [RelayCommand]
    private async Task StopAsync()
    {
        var context = global::Microsoft.Maui.ApplicationModel.Platform.AppContext;
        var intent = new Intent(context, typeof(ProxyForegroundService));
        intent.SetAction(ProxyForegroundService.ActionStop);
        context.StartService(intent);

        // сервис гасится асинхронно (StopSelf -> OnDestroy -> Shutdown) — ждём, пока порт освободится
        for (var i = 0; i < 20 && ProxyForegroundService.IsRunning; i++)
            await Task.Delay(150);

        Refresh();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        Refresh();
        await Task.CompletedTask;
    }

    /// <summary>Копирует адрес подключения (IP:порт), чтобы не вводить его вручную на ноутбуке.</summary>
    [RelayCommand]
    private async Task CopyAddressAsync()
    {
        if (!IsRunning) return;

        try
        {
            await Clipboard.SetTextAsync(ClientAddress);
            DetailText = "Адрес скопирован";
        }
        catch (Exception ex)
        {
            DetailText = $"Не удалось скопировать: {ex.Message}";
        }
    }

    /// <summary>Раз в секунду обновляем показания: счётчики трафика растут во время работы.</summary>
    public void StartUiTimer()
    {
        if (_uiTimer is not null) return;

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null) return;

        _uiTimer = dispatcher.CreateTimer();
        _uiTimer.Interval = TimeSpan.FromSeconds(1);
        _uiTimer.Tick += (_, _) => Refresh();
        _uiTimer.Start();
    }

    public void StopUiTimer()
    {
        _uiTimer?.Stop();
        _uiTimer = null;
    }

    public void Refresh()
    {
      if (!global::Microsoft.Maui.ApplicationModel.MainThread.IsMainThread)
    {
        global::Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(Refresh);
        return;
    }
        try
        {
            IsRunning = ProxyForegroundService.IsRunning;

            var port = ProxyForegroundService.ActivePort;
            if (port > 0) PortText = port.ToString();

            IpAddress = IsRunning
            ? ProxyForegroundService.AdvertisedHost
            : ResolveDisplayAddress();

            StatusText = IsRunning ? "Включено" : "Выключено";

            if (IsRunning)
            {
                DetailText = $"Ноутбук подключается к {ProxyForegroundService.AdvertisedHost}:{port}";
                Remember(true, DetailText);
            }
            else if (_lastFailed && _lastMessage is not null &&
                     DateTime.UtcNow - _lastAt < TimeSpan.FromSeconds(25))
            {
                // Причина отказа живёт дольше одного тика таймера.
                DetailText = _lastMessage;
            }
            else
            {
                DetailText = "Нажмите кольцо, чтобы включить";
            }

            var stats = ProxyForegroundService.Stats;
            var now = DateTime.UtcNow;

            if (IsRunning && _lastStatsAt != DateTime.MinValue)
            {
                var elapsed = (now - _lastStatsAt).TotalSeconds;
                if (elapsed > 0.2)
                {
                    var deltaDown = Math.Max(0, stats.BytesDown - _lastStatsDown);
                    var deltaUp = Math.Max(0, stats.BytesUp - _lastStatsUp);
                    SpeedDown = $"↓ {FormatBytes((long)(deltaDown / elapsed))}/с";
                    SpeedUp = $"↑ {FormatBytes((long)(deltaUp / elapsed))}/с";
                }
            }
            else if (!IsRunning)
            {
                SpeedDown = "↓ 0 Б/с";
                SpeedUp = "↑ 0 Б/с";
            }

            _lastStatsAt = now;
            _lastStatsUp = stats.BytesUp;
            _lastStatsDown = stats.BytesDown;

            TrafficUp = $"↑ {FormatBytes(stats.BytesUp)}";
            TrafficDown = $"↓ {FormatBytes(stats.BytesDown)}";
            ActiveConnections = $"{stats.ActiveConnections} / {stats.TotalConnections}";

            LogText = ProxyForegroundService.LogText;

            PowerText = IsRunning ? "Включено" : "Выключено";
            PowerSubText = IsRunning ? $"порт {port}" : "нажмите, чтобы включить";
            PowerTextColor = IsRunning ? RunningColor : IdleColor;
            PowerStroke = new SolidColorBrush(IsRunning ? RunningColor : IdleStroke);
            PowerGlowOpacity = IsRunning ? 0.7 : 0;

            OnPropertyChanged(nameof(ClientAddress));
        }
        catch (Exception ex)
        {
            // Обновление интерфейса не должно никогда ронять приложение
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] Refresh: {ex}");
            DetailText = $"Не удалось обновить состояние: {ex.Message}";
        }
    }

    private async Task EnsureNotificationPermissionAsync()
    {
        try
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(33))
                await Permissions.RequestAsync<Permissions.PostNotifications>();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] notification permission: {ex.Message}");
        }
    }

    /// <summary>
    /// IP, который увидят клиенты: адрес интерфейса точки доступа, пока прокси выключен.
    /// </summary>
    private static string ResolveDisplayAddress()
    {
        var context = global::Microsoft.Maui.ApplicationModel.Platform.AppContext;
        var address = HotspotIpResolver.ResolveAdvertisedAddress(context);
        return address?.ToString() ?? "—";
    }

    /// <summary>Человекочитаемый размер: Б, КБ, МБ, ГБ.</summary>
    public static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "0 Б";
        if (bytes < 1024) return $"{bytes} Б";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:0.#} КБ";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):0.#} МБ";
        return $"{bytes / (1024.0 * 1024 * 1024):0.##} ГБ";
    }
}
