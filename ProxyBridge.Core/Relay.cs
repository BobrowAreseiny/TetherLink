using System.Buffers;
using System.Net.Sockets;

namespace ProxyBridge.Core;

/// <summary>Двунаправленная перекачка потоков без накопления в памяти (буфер 64 КБ).</summary>
internal static class Relay
{
    private const int BufferSize = 64 * 1024;

    /// <summary>Как часто сообщать о прогрессе во время длинной передачи.</summary>
    private const int ProgressIntervalMs = 500;

    /// <summary>
    /// Перекачка в обе стороны. <paramref name="onProgress"/> вызывается не чаще двух раз в секунду,
    /// пока идёт трафик — иначе счётчики в интерфейсе показывали бы 0 до закрытия соединения.
    /// </summary>
    public static async Task PipeAsync(Stream a, Stream b, CancellationToken ct,
        CountingStream? counterA = null, CountingStream? counterB = null, Action? onProgress = null)
    {
        var ab = PumpAsync(a, b, ct, onProgress);
        var ba = PumpAsync(b, a, ct, onProgress);

        await Task.WhenAny(ab, ba).ConfigureAwait(false);

        // даём второй стороне шанс дописать хвост, но не висим вечно
        try
        {
            await Task.WhenAll(ab, ba).WaitAsync(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException or TimeoutException)
        {
            // штатное завершение туннеля
        }
    }

    /// <summary>Копирование одного направления с периодическим уведомлением о прогрессе.</summary>
    private static async Task PumpAsync(Stream from, Stream to, CancellationToken ct, Action? onProgress)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        var lastReport = Environment.TickCount64;

        try
        {
            while (true)
            {
                var read = await from.ReadAsync(buffer.AsMemory(0, BufferSize), ct).ConfigureAwait(false);
                if (read == 0) break;

                await to.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);

                if (onProgress is not null && Environment.TickCount64 - lastReport >= ProgressIntervalMs)
                {
                    lastReport = Environment.TickCount64;
                    onProgress();
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static async Task<TcpClient> ConnectAsync(string host, int port, CancellationToken ct)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            await client.ConnectAsync(host, port, ct).ConfigureAwait(false);
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }
}

/// <summary>Обёртка-счётчик (для IStatsSink), опционально используется хендлерами.</summary>
internal sealed class CountingStream(Stream inner) : Stream
{
    /// <summary>Исходный поток (нужно, чтобы достать сокет и endpoint).</summary>
    public Stream Inner { get; } = inner;

    public long BytesRead { get; private set; }
    public long BytesWritten { get; private set; }

    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Важно: нельзя читать t.Result после await t — для ValueTask, завязанного
        // на IValueTaskSource, это даёт «The result of the operation was already consumed».
        // Значение считаем прямо из await.
        var n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        BytesRead += n;
        return n;
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var t = inner.WriteAsync(buffer, cancellationToken);
        BytesWritten += buffer.Length;
        return t;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count)
    {
        var n = inner.Read(buffer, offset, count);
        BytesRead += n;
        return n;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        inner.Write(buffer, offset, count);
        BytesWritten += count;
    }

    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) inner.Dispose();
        base.Dispose(disposing);
    }
}
