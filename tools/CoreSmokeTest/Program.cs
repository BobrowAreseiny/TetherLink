using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyBridge.Core;
using ProxyBridge.Core.Abstractions;

var failures = new List<string>();
void Check(string name, bool ok, string? detail = null)
{
    Console.WriteLine($"{(ok ? "OK  " : "FAIL")}  {name}{(detail is null ? "" : "  -> " + detail)}");
    if (!ok) failures.Add(name);
}

// ---------- 1. PAC-файл отдаётся по HTTP ----------
var stats = new TrafficStats();
var auth = new BasicAuthValidator("user", "pass");
var server = new ProxyServer(IPAddress.Loopback, 19080, new ProxyServerOptions
{
    Auth = auth,
    Stats = stats,
    AdvertisedHost = IPAddress.Parse("192.168.43.1"),
    EnablePac = true,
    Port = 19080,
});
server.Start();
await Task.Delay(300);

using (var http = new TcpClient())
{
    await http.ConnectAsync(IPAddress.Loopback, 19080);
    var stream = http.GetStream();
    var req = Encoding.ASCII.GetBytes("GET http://wpad/proxy.pac HTTP/1.1\r\nHost: wpad\r\n\r\n");
    await stream.WriteAsync(req);
    await stream.FlushAsync();

    var buffer = new byte[8192];
    var read = await stream.ReadAsync(buffer);
    var text = Encoding.UTF8.GetString(buffer, 0, read);

    Check("PAC отдаётся без авторизации", text.StartsWith("HTTP/1.1 200 OK"), text.Split('\r')[0]);
    Check("PAC содержит PROXY 192.168.43.1:19080", text.Contains("PROXY 192.168.43.1:19080"));
    Check("PAC содержит SOCKS5", text.Contains("SOCKS5 192.168.43.1:19080"));
    Check("PAC отдаёт application/x-ns-proxy-autoconfig", text.Contains("application/x-ns-proxy-autoconfig"));
}

// ---------- 2. Авторизация: без пароля → 407 ----------
using (var http = new TcpClient())
{
    await http.ConnectAsync(IPAddress.Loopback, 19080);
    var stream = http.GetStream();
    var req = Encoding.ASCII.GetBytes("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
    await stream.WriteAsync(req);
    await stream.FlushAsync();

    var buffer = new byte[4096];
    var read = await stream.ReadAsync(buffer);
    var text = Encoding.ASCII.GetString(buffer, 0, read);
    Check("Без пароля прокси отвечает 407", text.Contains("407 Proxy Authentication Required"), text.Split('\r')[0]);
}

// ---------- 3. Авторизация: с паролем → CONNECT работает ----------
using (var http = new TcpClient())
{
    await http.ConnectAsync(IPAddress.Loopback, 19080);
    var stream = http.GetStream();
    var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
    var req = Encoding.ASCII.GetBytes(
        $"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {creds}\r\n\r\n");
    await stream.WriteAsync(req);
    await stream.FlushAsync();

    var buffer = new byte[4096];
    var read = await stream.ReadAsync(buffer);
    var text = Encoding.ASCII.GetString(buffer, 0, read);
    Check("С верным паролем CONNECT отвечает 200", text.Contains("200 Connection Established"), text.Split('\r')[0]);
}

// ---------- 4. Неверный пароль → 407 ----------
using (var http = new TcpClient())
{
    await http.ConnectAsync(IPAddress.Loopback, 19080);
    var stream = http.GetStream();
    var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:wrong"));
    var req = Encoding.ASCII.GetBytes(
        $"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {creds}\r\n\r\n");
    await stream.WriteAsync(req);
    await stream.FlushAsync();

    var buffer = new byte[4096];
    var read = await stream.ReadAsync(buffer);
    var text = Encoding.ASCII.GetString(buffer, 0, read);
    Check("С неверным паролем CONNECT отвечает 407", text.Contains("407"), text.Split('\r')[0]);
}

// ---------- 5. SOCKS5 UDP ASSOCIATE (на сервере без авторизации) ----------
var openServer = new ProxyServer(IPAddress.Loopback, 19081, new ProxyServerOptions
{
    AdvertisedHost = IPAddress.Loopback,
    EnablePac = false,
    Port = 19081,
    Log = m => Console.WriteLine($"      [server] {m}"),
});
openServer.Start();
await Task.Delay(300);

using (var socks = new TcpClient())
{
    await socks.ConnectAsync(IPAddress.Loopback, 19081);
    var stream = socks.GetStream();

    // Greeting: SOCKS5, 1 метод, no-auth
    await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
    await stream.FlushAsync();

    var buffer = new byte[1024];
    var read = await stream.ReadAsync(buffer);
    Check("SOCKS5: сервер выбрал метод", read >= 2 && buffer[0] == 0x05 && buffer[1] == 0x00,
        $"ver={buffer[0]} method={buffer[1]}");

    // UDP ASSOCIATE: VER=5 CMD=3 RSV=0 ATYP=1 0.0.0.0:0
    await stream.WriteAsync(new byte[] { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
    await stream.FlushAsync();

    var read2 = await stream.ReadAsync(buffer);
    Check("SOCKS5: UDP ASSOCIATE принят", read2 >= 2 && buffer[0] == 0x05 && buffer[1] == 0x00,
        $"reply={buffer[0]:X2} {buffer[1]:X2}");
    Check("SOCKS5: сервер вернул UDP-порт", read2 >= 10 && buffer[9] != 0,
        read2 >= 10 ? $"port={buffer[8] * 256 + buffer[9]}" : "short reply");
}

// ---------- 8. Проверка связи (ProxyProbe) ----------
var (probeOk, probeMsg) = await ProxyProbe.CheckAsync("127.0.0.1", 19081);
Check("ProxyProbe: живой прокси найден", probeOk, probeMsg);

var (probeBad, probeBadMsg) = await ProxyProbe.CheckAsync("127.0.0.1", 19099);
Check("ProxyProbe: закрытый порт даёт внятную ошибку",
    !probeBad && !probeBadMsg.Contains("No such host", StringComparison.OrdinalIgnoreCase),
    probeBadMsg);

var (probeZero, probeZeroMsg) = await ProxyProbe.CheckAsync("0.0.0.0", 9000);
Check("ProxyProbe: 0.0.0.0 отклонён", !probeZero && probeZeroMsg.Contains("0.0.0.0"), probeZeroMsg);

var (probeName, probeNameMsg) = await ProxyProbe.CheckAsync("телефон.local", 9000);
Check("ProxyProbe: имя вместо IP отклонено", !probeName && probeNameMsg.Contains("числом"), probeNameMsg);

openServer.Stop();
await openServer.DisposeAsync();

// ---------- 9. HTTP GET через прокси (absolute-form) ----------
using (var http = new TcpClient())
{
    await http.ConnectAsync(IPAddress.Loopback, 19080);
    var stream = http.GetStream();
    var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
    var req = Encoding.ASCII.GetBytes(
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n" +
        $"Proxy-Authorization: Basic {creds}\r\nConnection: close\r\n\r\n");

    await stream.WriteAsync(req);
    await stream.FlushAsync();

    using var ms = new MemoryStream();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    try
    {
        await stream.CopyToAsync(ms, cts.Token);
    }
    catch (Exception) { /* разрыв после ответа — нормален */ }

    var text = Encoding.UTF8.GetString(ms.ToArray());
    Check("HTTP GET через прокси возвращает 200", text.Contains("200 OK"), text.Split('\r').FirstOrDefault());
    Check("HTTP GET через прокси отдаёт тело ответа", text.Contains("Example Domain", StringComparison.OrdinalIgnoreCase));
}

// ---------- 10. SOCKS5 CONNECT (TCP) с авторизацией ----------
using (var socks = new TcpClient())
{
    await socks.ConnectAsync(IPAddress.Loopback, 19080);
    var stream = socks.GetStream();

    // greeting с поддержкой пароля
    await stream.WriteAsync(new byte[] { 0x05, 0x02, 0x00, 0x02 });
    await stream.FlushAsync();

    var buf = new byte[16];
    var n = await stream.ReadAsync(buf);
    Check("SOCKS5: выбран метод пароля", n >= 2 && buf[1] == 0x02, $"method={buf[1]}");

    // RFC 1929: ver=1, len, user, len, pass
    var user = Encoding.ASCII.GetBytes("user");
    var pass = Encoding.ASCII.GetBytes("pass");
    var authPacket = new List<byte> { 0x01, (byte)user.Length };
    authPacket.AddRange(user);
    authPacket.Add((byte)pass.Length);
    authPacket.AddRange(pass);

    await stream.WriteAsync(authPacket.ToArray());
    await stream.FlushAsync();

    n = await stream.ReadAsync(buf);
    Check("SOCKS5: пароль принят", n >= 2 && buf[1] == 0x00, $"status={buf[1]}");

    // CONNECT example.com:80 (домен, ATYP=3)
    var hostName = Encoding.ASCII.GetBytes("example.com");
    var connect = new List<byte> { 0x05, 0x01, 0x00, 0x03, (byte)hostName.Length };
    connect.AddRange(hostName);
    connect.AddRange([0x00, 0x50]); // port 80

    await stream.WriteAsync(connect.ToArray());
    await stream.FlushAsync();

    n = await stream.ReadAsync(buf);
    Check("SOCKS5: CONNECT установлен", n >= 2 && buf[1] == 0x00, $"reply={buf[1]}");

    // реальный обмен данными через туннель
    await stream.WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"));
    await stream.FlushAsync();

    using var ms = new MemoryStream();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    try
    {
        await stream.CopyToAsync(ms, cts.Token);
    }
    catch (Exception) { /* разрыв после ответа — нормален */ }

    var text = Encoding.UTF8.GetString(ms.ToArray());
    Check("SOCKS5: данные идут через туннель", text.Contains("Example Domain", StringComparison.OrdinalIgnoreCase));
}

// ---------- 11. SOCKS5 UDP ASSOCIATE: реальный DNS-запрос ----------
var udpServer = new ProxyServer(IPAddress.Loopback, 19082, new ProxyServerOptions
{
    AdvertisedHost = IPAddress.Loopback,
    EnablePac = false,
    Port = 19082,
    Log = m => Console.WriteLine($"      [udp] {m}"),
});
udpServer.Start();
await Task.Delay(200);

using (var control = new TcpClient())
{
    await control.ConnectAsync(IPAddress.Loopback, 19082);
    var stream = control.GetStream();

    await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
    await stream.FlushAsync();
    var buf = new byte[64];
    await stream.ReadAsync(buf);

    await stream.WriteAsync(new byte[] { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
    await stream.FlushAsync();

    var n = await stream.ReadAsync(buf);
    var relayPort = n >= 10 ? (buf[8] << 8) | buf[9] : 0;
    Check("UDP: сервер выдал relay-порт", relayPort > 0, $"port={relayPort}");

    if (relayPort > 0)
    {
        // Герметичная проверка: локальный UDP-эхо-сервер вместо внешнего DNS
        // (внешний резолвер может быть недоступен — тест не должен от этого зависеть).
        using var echo = new UdpClient(new IPEndPoint(IPAddress.Loopback, 19090));
        var echoPort = ((IPEndPoint)echo.Client.LocalEndPoint!).Port;

        var echoTask = Task.Run(async () =>
        {
            try
            {
                var incoming = await echo.ReceiveAsync();
                await echo.SendAsync(incoming.Buffer, incoming.Buffer.Length, incoming.RemoteEndPoint);
            }
            catch { /* тест завершился */ }
        });

        // SOCKS5 UDP-заголовок: RSV(2) FRAG(1) ATYP=IPv4 ADDR=127.0.0.1 PORT + DATA
        var echoQuery = new List<byte> { 0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, (byte)(echoPort >> 8), (byte)(echoPort & 0xFF) };
        var payload = Encoding.ASCII.GetBytes("ping-through-socks5-udp");
        echoQuery.AddRange(payload);

        using var udp = new UdpClient();
        udp.Connect(IPAddress.Loopback, relayPort);
        await udp.SendAsync(echoQuery.ToArray(), echoQuery.Count);

        var receive = udp.ReceiveAsync();
        var done = await Task.WhenAny(receive, Task.Delay(5000));
        Check("UDP: ответ пришёл через релей", done == receive,
            done == receive ? $"{receive.Result.Buffer.Length} байт" : "таймаут");

        if (done == receive)
        {
            var reply = receive.Result.Buffer;
            // Заголовок: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) = 10 байт, дальше — данные
            var okHeader = reply.Length >= 10 && reply[0] == 0 && reply[2] == 0 && reply[3] == 0x01;
            Check("UDP: заголовок ответа корректный", okHeader, $"{reply.Length} байт");

            var body = reply.Length > 10 ? Encoding.ASCII.GetString(reply, 10, reply.Length - 10) : string.Empty;
            Check("UDP: данные не искажены", body == "ping-through-socks5-udp", body);
        }

        await echoTask.WaitAsync(TimeSpan.FromSeconds(2)).ContinueWith(_ => { });
    }
}

udpServer.Stop();
await udpServer.DisposeAsync();

// ---------- 7. Счётчики трафика ----------
var snapshot = stats.Snapshot();
Check("Счётчики: соединения учитываются", snapshot.TotalConnections > 0,
    $"total={snapshot.TotalConnections}");
Check("Счётчики: байты от клиента учтены", snapshot.BytesUp > 0, $"up={snapshot.BytesUp}");
Check("Счётчики: байты клиенту учтены", snapshot.BytesDown > 0, $"down={snapshot.BytesDown}");

server.Stop();
await server.DisposeAsync();

// ---------- 12. Формат системного прокси ----------
Check("ProxyFormat: корректная строка",
    ProxyFormat.BuildServerString("127.0.0.1", 9000) == "http=127.0.0.1:9000;https=127.0.0.1:9000",
    ProxyFormat.BuildServerString("127.0.0.1", 9000));

Check("ProxyFormat: IP телефона",
    ProxyFormat.BuildServerString("192.168.43.1", 9000) == "http=192.168.43.1:9000;https=192.168.43.1:9000");

Check("ProxyFormat: подпись вместо адреса отклонена",
    !ProxyFormat.IsValidHost("127.0.0.1 (через adb)"), "127.0.0.1 (через adb)");

Check("ProxyFormat: пустой адрес отклонён", !ProxyFormat.IsValidHost("  "));

var badThrew = false;
try { ProxyFormat.BuildServerString("127.0.0.1 (через adb)", 9000); }
catch (ArgumentException) { badThrew = true; }
Check("ProxyFormat: некорректный адрес не попадает в реестр", badThrew);

Console.WriteLine();
Console.WriteLine(failures.Count == 0
    ? "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"
    : $"ПРОВАЛЕНО: {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;
