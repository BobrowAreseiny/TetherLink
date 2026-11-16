
namespace ProxyBridge.Core.Abstractions;

/// <summary>
/// Проверка учётных данных для режима «прокси по Wi-Fi» (без adb).
/// Реализации: Basic (HTTP 407) и username/password (SOCKS5, RFC 1929).
/// </summary>
public interface IAuthValidator
{
    /// <summary>true, если пара логин/пароль допустима. null = «без пароля».</summary>
    bool Validate(string? userName, string? password);
}
