
namespace ProxyBridge.Core.Abstractions;

/// <summary>Счётчики трафика и активных соединений — для UI.</summary>
public interface IStatsSink
{
    void OnConnectionOpened(long connectionId, string host, int port);
    void OnBytesTransferred(long connectionId, long bytesFromClient, long bytesToClient);
    void OnConnectionClosed(long connectionId, string? error = null);

    /// <summary>
    /// Абсолютные счётчики соединения (байты от клиента / клиенту).
    /// Нужны для живого обновления во время длинной передачи: реализации считают дельту сами.
    /// </summary>
    void ReportAbsolute(long connectionId, long bytesFromClient, long bytesToClient);
}
