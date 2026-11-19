using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Net.Wifi;
using Android.OS;
using AndroidX.Core.App;
using ProxyBridge.Core;

namespace ProxyBridge.Android.Services;

/// <summary>
/// Foreground-сервис, внутри которого живёт прокси-сервер.
/// Режим один — точка доступа: слушаем 0.0.0.0 и публикуем адрес телефона в сети точки доступа.
/// Если точки доступа нет, сервер не поднимается вообще: клиент на ноутбуке всё равно
/// не смог бы подключиться, а «включено» на экране было бы враньём.
/// </summary>
[Service(Name = "com.example.proxybridge.ProxyForegroundService",
         Exported = false,
         ForegroundServiceType = ForegroundService.TypeSpecialUse)]
public sealed class ProxyForegroundService : Service
{
    public const string ActionStart = "com.example.proxybridge.action.START";
    public const string ActionStop = "com.example.proxybridge.action.STOP";
    public const string ExtraPort = "port";

    private const string ChannelId = "proxybridge";
    private const int NotificationId = 1001;

    private static ProxyServer? _server;
    private static TrafficStats? _stats;
    private static string? _advertisedHost;
    private static string _lastError = string.Empty;
    private static readonly List<string> _log = [];
    private static readonly object _logSync = new();

    private PowerManager.WakeLock? _wakeLock;
    private WifiManager.WifiLock? _wifiLock;
    private System.Threading.Timer? _idleTimer;

    /// <summary>Когда последний раз через прокси прошёл байт: используется для
    /// автоматического отпускания wake lock, чтобы не жечь батарею в простое.</summary>
    private static DateTime _lastTrafficAt = DateTime.UtcNow;

    /// <summary>Фактический порт. 0, если сервер не запущен.</summary>
    public static int ActivePort => _server?.Port ?? 0;

    public static bool IsRunning => _server is { IsRunning: true };

    /// <summary>Адрес в сети точки доступа, который указывают на ноутбуке.</summary>
    public static string AdvertisedHost => _advertisedHost ?? "—";

    /// <summary>Последняя ошибка (например, точка доступа не найдена или порт занят).</summary>
    public static string LastError
    {
        get { lock (_logSync) return _lastError; }
    }

    /// <summary>Счётчики трафика.</summary>
    public static TrafficStats.StatsSnapshot Stats => _stats?.Snapshot() ?? default;

    /// <summary>Журнал событий (последние записи).</summary>
    public static string LogText
    {
        get { lock (_logSync) return string.Join("\n", _log.TakeLast(10)); }
    }

    /// <summary>Остановить сервис снаружи (например, из Activity.OnDestroy).</summary>
    public static void RequestStop(Context context)
    {
        try
        {
            var intent = new Intent(context, typeof(ProxyForegroundService));
            intent.SetAction(ActionStop);
            context.StopService(intent);
        }
        catch (Exception ex)
        {
            Log($"stop request failed: {ex.Message}");
        }
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        // Перезапуск системой (Sticky) приходит с null-intent: настроек в нём нет,
        // а поднимать прокси без ведома пользователя нельзя.
        if (intent is null)
        {
            Log("Сервис перезапущен системой без настроек — останавливаемся");
            StopSelf();
            return StartCommandResult.NotSticky;
        }

        if (intent.Action == ActionStop)
        {
            Shutdown();
            StopSelf();
            return StartCommandResult.NotSticky;
        }

        var port = intent.GetIntExtra(ExtraPort, 9000);

        CreateChannel();

        var notification = BuildNotification(port);
        if (OperatingSystem.IsAndroidVersionAtLeast(34))
            StartForeground(NotificationId, notification, ForegroundService.TypeSpecialUse);
        else
            StartForeground(NotificationId, notification);

        AcquireWakeLock();
        _ = StartServerAsync(port);

        // Таймер проверки бездействия: если 30 секунд нет активного соединения,
        // отпускаем partial wake lock (CPU снова может спать). Wifi lock остаётся,
        // чтобы входящие пакеты от ноутбука будили процессор. Как только появится
        // новое соединение — wake lock подхватится снова в UpdateWakeLockForTraffic.
        StopIdleTimer();
        _idleTimer = new System.Threading.Timer(_ => CheckIdleWakeLock(), null,
            TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));

        return StartCommandResult.NotSticky;
    }

    private async Task StartServerAsync(int port)
    {
        if (_server is not null) return;

        lock (_logSync) _lastError = string.Empty;

        // Точка доступа обязательна: без её адреса ноутбуку некуда подключаться.
        var hotspotIp = HotspotIpResolver.ResolveAdvertisedAddress(this);
        if (hotspotIp is null)
        {
            SetError("Точка доступа не найдена — включите её и нажмите кольцо снова");
            // Не убиваем сервис: телефон мог на секунду выключить точку доступа или
            // переподключиться. Сервис останется в фоне, и как только адрес появится,
            // пользователь сможет нажать кольцо повторно без переустановки.
            return;
        }

        if (!HotspotIpResolver.InHotspotSubnet(hotspotIp))
            Log($"Интерфейс точки доступа не найден — публикуем адрес {hotspotIp}");

        // ЖЁСТКАЯ ЗАЩИТА: если стелс-маскировка трафика недоступна,
        // сервер даже не стартует — иначе оператор увидит «голый» трафик.
        try
        {
            CarrierStealthFilter.EnsureStealthOrThrow();
        }
        catch (Exception ex)
        {
            SetError($"Защита трафика недоступна: {ex.Message}");
            Log($"Отказ запуска сервера: {ex.Message}");
            StopSelf();
            return;
        }

        var stats = new TrafficStats();
        var options = new ProxyServerOptions
        {
            Stats = stats,
            Log = Log,
            AdvertisedHost = hotspotIp,
            Port = port,
        };

        var server = new ProxyServer(System.Net.IPAddress.Any, port, options);
        try
        {
            server.Start();
            _server = server;
            _stats = stats;
            _advertisedHost = hotspotIp.ToString();

            Log($"Сервер запущен: 0.0.0.0:{server.Port}");
            Log($"Ноутбук подключается к {AdvertisedHost}:{server.Port}");
        }
        catch (Exception ex)
        {
            SetError(ex.Message);
            Log($"Не удалось запустить сервер: {ex.Message}");
            await server.DisposeAsync();
            StopSelf();
        }
    }

    private static void SetError(string message)
    {
        lock (_logSync) _lastError = message;
        Log(message);
    }

    private static void Log(string message)
    {
        System.Diagnostics.Debug.WriteLine($"[ProxyBridge] {message}");
        lock (_logSync)
        {
            _log.Add($"{DateTime.Now:HH:mm:ss}  {message}");
            if (_log.Count > 200) _log.RemoveRange(0, _log.Count - 200);
        }
    }

    private void CreateChannel()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.O) return;

        var manager = (NotificationManager?)GetSystemService(NotificationService)!;
        if (manager?.GetNotificationChannel(ChannelId) is not null) return;

        var channel = new NotificationChannel(ChannelId, "TetherLink", NotificationImportance.Low)
        {
            Description = "Прокси для подключения ноутбука через точку доступа"
        };
        manager?.CreateNotificationChannel(channel);
    }

    private Notification BuildNotification(int port)
    {
        var stopIntent = new Intent(this, typeof(ProxyForegroundService));
        stopIntent.SetAction(ActionStop);
        var stopPending = PendingIntent.GetService(this, 1, stopIntent, PendingIntentFlags.Immutable)!;

        var builder = new NotificationCompat.Builder(this, ChannelId)!;
        builder.SetContentTitle("TetherLink");
        builder.SetContentText($"Прокси в точке доступа, порт {port}");
        builder.SetSmallIcon(global::Android.Resource.Drawable.IcDialogInfo);
        builder.SetOngoing(true);
        builder.SetPriority(NotificationCompat.PriorityLow);
        builder.AddAction(0, "Стоп", stopPending);
        return builder.Build()!;
    }

    private void AcquireWakeLock()
    {
        if (_wakeLock is not null) return;
        var pm = (PowerManager?)GetSystemService(PowerService)!;
        _wakeLock = pm?.NewWakeLock(WakeLockFlags.Partial, "ProxyBridge::proxy");
        _wakeLock?.SetReferenceCounted(false);
        _wakeLock?.Acquire();

        // WifiLock держит Wi-Fi-радио включённым, но позволяет процессору уходить в сон,
        // пока нет пакетов. Это экономит батарею по сравнению с полным wake lock и
        // гарантирует, что Samsung/One UI не отключит Wi-Fi-приёмник при заблокированном экране.
        if (_wifiLock is null)
        {
            var wm = (WifiManager?)GetSystemService(WifiService)!;
            _wifiLock = wm?.CreateWifiLock(global::Android.Net.WifiMode.Full, "ProxyBridge::wifi");
            _wifiLock?.SetReferenceCounted(false);
            _wifiLock?.Acquire();
        }
    }

    private void ReleaseWakeLock()
    {
        if (_wifiLock is { IsHeld: true }) _wifiLock.Release();
        _wifiLock = null;

        if (_wakeLock is { IsHeld: true }) _wakeLock.Release();
        _wakeLock = null;
    }

    private void StopIdleTimer()
    {
        var timer = _idleTimer;
        _idleTimer = null;
        timer?.Dispose();
    }

    /// <summary>Экономим батарею: если 30 секунд нет активного соединения,
    /// отпускаем partial wake lock. Wifi lock оставляем — он экономнее и
    /// достаточен, чтобы входящие пакеты от ноутбука разбудили процессор.</summary>
    private void CheckIdleWakeLock()
    {
        if (_server is null) return;

        try
        {
            var snap = _stats?.Snapshot() ?? default;

            if (snap.ActiveConnections > 0)
            {
                _lastTrafficAt = DateTime.UtcNow;

                // Пока есть активное соединение — wake lock нужен: CPU должен быть
                // включён, чтобы обработать Relay-потоки и ответ серверу.
                if (_wakeLock is null) AcquireWakeLock();
                return;
            }

            var idle = DateTime.UtcNow - _lastTrafficAt;
            if (idle.TotalSeconds > 30 && _wakeLock is not null)
            {
                // В простое CPU может спать: только Wi-Fi-radio держится wifi lock.
                if (_wakeLock.IsHeld) _wakeLock.Release();
                _wakeLock = null;
            }
        }
        catch
        {
            // Проверка бездействия не должна ронять сервис.
        }
    }
    /// <summary>Гасим сервер синхронно: listener закрывается сразу, порт освобождается.</summary>
    private void Shutdown()
    {
        StopIdleTimer();

        var server = _server;
        _server = null;

        if (server is not null)
        {
            server.Stop();
            _ = server.DisposeAsync().AsTask();
        }

        _stats = null;
        _advertisedHost = null;

        ReleaseWakeLock();
        Log("Сервер остановлен, порт освобождён");
    }

    public override void OnDestroy()
    {
        Shutdown();
        base.OnDestroy();
    }

    public override void OnTaskRemoved(Intent? rootIntent)
    {
        // Сервис должен продолжать работать, даже если пользователь смахнул приложение из недавних.
        // foregroundServiceType=specialUse и wake lock удерживают сервис в фоне.
        // На Samsung это особенно важно: без stopWithTask=false система убивает сервис при
        // очистке стека задач, и соединение с ноутбуком обрывается.
        Log("Приложение убрано из списка задач — прокси продолжает работать");
        base.OnTaskRemoved(rootIntent);
    }

    public override IBinder? OnBind(Intent? intent) => null;
}
