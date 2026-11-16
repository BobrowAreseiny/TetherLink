using System.Net;
using System.Net.Sockets;
using ProxyBridge.Core.Abstractions;

namespace ProxyBridge.Core;

/// <summary>
/// Точка входа ядра. Не знает ничего про Android/Windows: только TCP + абстракции.
/// </summary>
public sealed class ProxyServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly IAuthValidator? _auth;
    private readonly IStatsSink? _stats;
    private readonly Action<string>? _log;
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<Task> _handlers = [];
    private readonly Lock _sync = new();
    private Task? _acceptLoop;
    private long _lastId;

    /// <summary>Адрес, который клиенты видят в PAC (для hotspot это IP точки доступа).</summary>
    private readonly IPAddress _advertisedHost;
    private readonly bool _enablePac;

    public ProxyServer(IPAddress bind, int port, IAuthValidator? auth = null, IStatsSink? stats = null, Action<string>? log = null)
        : this(bind, port, new ProxyServerOptions { Auth = auth, Stats = stats, Log = log, Port = port })
    {
    }

    public ProxyServer(IPAddress bind, int port, ProxyServerOptions options)
    {
        _listener = new TcpListener(bind, port);
        _auth = options.Auth;
        _stats = options.Stats;
        _log = options.Log;
        _advertisedHost = options.AdvertisedHost;
        _enablePac = options.EnablePac;
        _port = options.Port;
    }

    private readonly int _port;

    public IPEndPoint? LocalEndPoint => _listener.LocalEndpoint as IPEndPoint;

    public int Port => LocalEndPoint?.Port ?? 0;

    /// <summary>URL PAC-файла, который отдаёт этот сервер. Пусто, если адрес неизвестен.</summary>
    public string PacUrl => _advertisedHost.Equals(System.Net.IPAddress.Any)
        ? string.Empty
        : $"http://{FormatHost(_advertisedHost)}:{Port}/proxy.pac";

    private static string FormatHost(IPAddress address)
        => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();

    public bool IsRunning => _acceptLoop is { IsCompleted: false };

    /// <summary>Запускает listener и возвращает управление; цикл приёма живёт в фоне.</summary>
    public void Start()
    {
        _listener.Start();
        _log?.Invoke($"ProxyBridge listening on {_listener.LocalEndpoint}");
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    /// <summary>Совместимо с примером из ТЗ: блокирующий вариант.</summary>
    public Task RunAsync(CancellationToken ct = default)
    {
        _listener.Start();
        return AcceptLoopAsync(ct);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"Accept failed: {ex.Message}");
                continue;
            }

            var task = HandleClientAsync(client, ct);
            lock (_sync) _handlers.Add(task);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            var id = Interlocked.Increment(ref _lastId);
            var remote = client.Client.RemoteEndPoint?.ToString();
            try
            {
                client.NoDelay = true;
                await using var stream = client.GetStream();

                var first = new byte[1];
                if (await client.Client.ReceiveAsync(first, SocketFlags.Peek, ct).ConfigureAwait(false) == 0)
                    return;

                _stats?.OnConnectionOpened(id, remote ?? "?", 0);

                if (first[0] == 0x05)
                {
                    await Socks5Handler.HandleAsync(stream, _auth, _stats, id, _log, ct).ConfigureAwait(false);
                }
                else
                {
                    await HttpProxyHandler.HandleAsync(stream, _auth, _stats, id, _log, ct, _enablePac ? _advertisedHost : null, Port).ConfigureAwait(false);
                }

                _stats?.OnConnectionClosed(id);
            }
            catch (OperationCanceledException)
            {
                _stats?.OnConnectionClosed(id);
            }
            catch (Exception ex)
            {
                _log?.Invoke($"#{id} failed: {ex.Message}");
                _stats?.OnConnectionClosed(id, ex.Message);
            }
            finally
            {
                lock (_sync)
                {
                    _handlers.RemoveWhere(t => t.IsCompleted);
                }
            }
        }
    }

    /// <summary>
    /// Синхронная остановка: listener закрывается немедленно, поэтому порт освобождается
    /// даже если процесс завершается и асинхронный код уже не доработает.
    /// </summary>
    public void Stop()
    {
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        try { _listener.Stop(); } catch (ObjectDisposedException) { }
    }

    public async Task StopAsync()
    {
        if (_cts.IsCancellationRequested) return;
        Stop();

        Task[] pending;
        lock (_sync) pending = [.. _handlers];
        try
        {
            await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        }
        catch
        {
            // не мешаем остановке
        }

        _log?.Invoke("ProxyBridge stopped");
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _cts.Dispose();
    }
}
