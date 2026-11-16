namespace ProxyBridge.Core;

/// <summary>
/// Параметры прокси-сервера. Собраны в один объект, чтобы не плодить длинные списки аргументов.
/// </summary>
public sealed class ProxyServerOptions
{
    /// <summary>Проверка логина/пароля. null — прокси открытый (только для 127.0.0.1).</summary>
    public Abstractions.IAuthValidator? Auth { get; init; }

    /// <summary>Счётчики трафика для UI.</summary>
    public Abstractions.IStatsSink? Stats { get; init; }

    /// <summary>Журнал событий.</summary>
    public Action<string>? Log { get; init; }

    /// <summary>
    /// Адрес, который клиенты используют для подключения. Нужен для PAC:
    /// телефон раздаёт точку доступа, клиент ходит на 192.168.43.1:9000, а не на 127.0.0.1.
    /// </summary>
    public System.Net.IPAddress AdvertisedHost { get; init; } = System.Net.IPAddress.Loopback;

    /// <summary>Раздавать PAC-файл (http://&lt;host&gt;:&lt;port&gt;/proxy.pac) и отвечать на WPAD-запросы.</summary>
    public bool EnablePac { get; init; } = true;

    /// <summary>Порт, на котором висит прокси (для PAC).</summary>
    public int Port { get; init; } = 9000;
}
