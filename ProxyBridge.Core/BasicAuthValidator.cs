using System.Security.Cryptography;
using System.Text;
using ProxyBridge.Core.Abstractions;

namespace ProxyBridge.Core;

/// <summary>
/// Проверка логина/пароля для HTTP (Basic, 407) и SOCKS5 (RFC 1929).
/// Сравнение — constant time, чтобы по задержке нельзя было подбирать пароль.
/// </summary>
public sealed class BasicAuthValidator : IAuthValidator
{
    private readonly byte[] _user;
    private readonly byte[] _password;

    public BasicAuthValidator(string userName, string password)
    {
        _user = Encoding.UTF8.GetBytes(userName ?? string.Empty);
        _password = Encoding.UTF8.GetBytes(password ?? string.Empty);
    }

    public bool Validate(string? userName, string? password)
    {
        var u = Encoding.UTF8.GetBytes(userName ?? string.Empty);
        var p = Encoding.UTF8.GetBytes(password ?? string.Empty);

        // CryptographicOperations.FixedTimeEquals требует одинаковой длины,
        // поэтому сравниваем хэши — длина исходных данных не утекает.
        var okUser = CryptographicOperations.FixedTimeEquals(SHA256.HashData(u), SHA256.HashData(_user));
        var okPass = CryptographicOperations.FixedTimeEquals(SHA256.HashData(p), SHA256.HashData(_password));
        return okUser & okPass;
    }
}
