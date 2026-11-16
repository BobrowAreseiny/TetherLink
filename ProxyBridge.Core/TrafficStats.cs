using ProxyBridge.Core.Abstractions;

namespace ProxyBridge.Core;

/// <summary>
/// Счётчики трафика: сколько байтов ушло в сеть и сколько вернулось клиенту,
/// сколько соединений сейчас активно. Данные читаются из UI потока.
/// </summary>
public sealed class TrafficStats : IStatsSink
{
    private readonly Lock _sync = new();
    private readonly Dictionary<long, (long FromClient, long ToClient)> _connections = [];

    private long _bytesUp;        // клиент → интернет
    private long _bytesDown;      // интернет → клиент
    private long _totalConnections;
    private long _activeConnections;
    private long _errors;

    public void OnConnectionOpened(long connectionId, string host, int port)
    {
        lock (_sync)
        {
            _connections[connectionId] = (0, 0);
            _totalConnections++;
            _activeConnections++;
        }
    }

    public void OnBytesTransferred(long connectionId, long bytesFromClient, long bytesToClient)
    {
        lock (_sync)
        {
            _bytesUp += bytesFromClient;
            _bytesDown += bytesToClient;
            if (_connections.TryGetValue(connectionId, out var counters))
                _connections[connectionId] = (counters.FromClient + bytesFromClient, counters.ToClient + bytesToClient);
        }
    }

    public void OnConnectionClosed(long connectionId, string? error = null)
    {
        lock (_sync)
        {
            if (_connections.Remove(connectionId))
                _activeConnections--;
            if (!string.IsNullOrEmpty(error))
                _errors++;
        }
    }

    /// <summary>
    /// Абсолютные счётчики соединения (для живого обновления во время передачи).
    /// Дельта считается здесь, чтобы не задвоить байты с OnBytesTransferred.
    /// </summary>
    public void ReportAbsolute(long connectionId, long bytesFromClient, long bytesToClient)
    {
        lock (_sync)
        {
            if (!_connections.TryGetValue(connectionId, out var current)) return;

            var addUp = bytesFromClient - current.FromClient;
            var addDown = bytesToClient - current.ToClient;
            if (addUp < 0) addUp = 0;
            if (addDown < 0) addDown = 0;

            _bytesUp += addUp;
            _bytesDown += addDown;
            _connections[connectionId] = (current.FromClient + addUp, current.ToClient + addDown);
        }
    }

    /// <summary>Счётчики трафика и активных соединений — для UI.</summary>
    public StatsSnapshot Snapshot()
    {
        lock (_sync)
        {
            return new StatsSnapshot(_bytesUp, _bytesDown, _activeConnections, _totalConnections, _errors);
        }
    }

    public void Reset()
    {
        lock (_sync)
        {
            _bytesUp = _bytesDown = _totalConnections = _activeConnections = _errors = 0;
            _connections.Clear();
        }
    }

    public readonly record struct StatsSnapshot(
        long BytesUp,
        long BytesDown,
        long ActiveConnections,
        long TotalConnections,
        long Errors);
}
