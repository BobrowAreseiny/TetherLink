using System.Net;
using ProxyBridge.Core;

// Локальный прокси-сервер, как на телефоне (без авторизации).
var server = new ProxyServer(IPAddress.Loopback, 19099, new ProxyServerOptions
{
    Stats = new TrafficStats(),
    Log = m => Console.WriteLine("  [server] " + m),
    AdvertisedHost = IPAddress.Loopback,
    Port = 19099,
});
server.Start();
await Task.Delay(300);

Console.WriteLine("== рабочий канал ==");
var good = await ProxyProbe.CheckEndToEndAsync("127.0.0.1", 19099);
Console.WriteLine($"ok={good.Ok}  {good.Message}");

// Порт, который никто не слушает — проверка обязана провалиться.
Console.WriteLine("== мёртвый порт ==");
var bad = await ProxyProbe.CheckEndToEndAsync("127.0.0.1", 19098);
Console.WriteLine($"ok={bad.Ok}  {bad.Message}");

// Порт, где слушает не прокси (обычный HTTP без CONNECT) — тоже провал.
Console.WriteLine("== чужой сервис ==");

var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 19097);
listener.Start();
_ = Task.Run(async () =>
{
    while (true)
    {
        var c = await listener.AcceptTcpClientAsync();
        var s = c.GetStream();
        await s.WriteAsync("HTTP/1.0 200 OK\r\n\r\n"u8.ToArray());
        c.Close();
    }
});
var alien = await ProxyProbe.CheckEndToEndAsync("127.0.0.1", 19097);
Console.WriteLine($"ok={alien.Ok}  {alien.Message}");

await server.DisposeAsync();
listener.Stop();

var pass = good.Ok && !bad.Ok && !alien.Ok;
Console.WriteLine(pass ? "RESULT: PASS" : "RESULT: FAIL");
return pass ? 0 : 1;
