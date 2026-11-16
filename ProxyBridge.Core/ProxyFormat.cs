using System.Net;

namespace ProxyBridge.Core;

/// <summary>
/// Р¤РѕСЂРјРёСЂРѕРІР°РЅРёРµ СЃС‚СЂРѕРєРё СЃРёСЃС‚РµРјРЅРѕРіРѕ РїСЂРѕРєСЃРё Рё РїСЂРѕРІРµСЂРєР° Р°РґСЂРµСЃР°.
///
/// Р—Р°С‡РµРј РѕС‚РґРµР»СЊРЅС‹Р№ РєР»Р°СЃСЃ: СЂР°РЅСЊС€Рµ РІ СЂРµРµСЃС‚СЂ Windows РїРѕРїР°РґР°Р»Р° СЃС‚СЂРѕРєР°
/// В«http=127.0.0.1 (С‡РµСЂРµР· adb):9000В» вЂ” РІ РЅР°СЃС‚СЂРѕР№РєРё СѓРµР·Р¶Р°Р» С‚РµРєСЃС‚ РґР»СЏ РёРЅС‚РµСЂС„РµР№СЃР°.
/// Chromium СЂР°Р·Р±РёСЂР°Р» В«127.0.0.1 (С‡РµСЂРµР· adb)В» РєР°Рє РёРјСЏ С…РѕСЃС‚Р°, DNS РЅРµ РЅР°С…РѕРґРёР» РµРіРѕ,
/// Рё РїРѕР»СЊР·РѕРІР°С‚РµР»СЊ РІРёРґРµР» В«С…РѕСЃС‚ РЅРµРёР·РІРµСЃС‚РµРЅВ». РўРµРїРµСЂСЊ Р°РґСЂРµСЃ РїСЂРѕРІРµСЂСЏРµС‚СЃСЏ РґРѕ Р·Р°РїРёСЃРё.
/// </summary>
public static class ProxyFormat
{
    /// <summary>РЎС‚СЂРѕРєР° РґР»СЏ HKCU\...\Internet Settings\ProxyServer.</summary>
    public static string BuildServerString(string host, int port)
    {
        if (!IsValidHost(host))
            throw new ArgumentException($"РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ Р°РґСЂРµСЃ РїСЂРѕРєСЃРё: В«{host}В»", nameof(host));

        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), $"РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РїРѕСЂС‚: {port}");

        return $"http={host}:{port};https={host}:{port}";
    }

    /// <summary>
    /// Р“РѕРґРёС‚СЃСЏ Р»Рё СЃС‚СЂРѕРєР° РєР°Рє Р°РґСЂРµСЃ РїСЂРѕРєСЃРё: IPv4/IPv6 РёР»Рё РґРѕРјРµРЅРЅРѕРµ РёРјСЏ.
    /// РџСЂРѕР±РµР»С‹, СЃРєРѕР±РєРё Рё РїСЂРѕС‡РёРµ РїРѕСЏСЃРЅРµРЅРёСЏ вЂ” РЅРµРґРѕРїСѓСЃС‚РёРјС‹.
    /// </summary>
    public static bool IsValidHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;

        var value = host.Trim();
        if (value.Length == 0) return false;

        // РќРёРєР°РєРёС… РїСЂРѕР±РµР»РѕРІ Рё СЃРєРѕР±РѕРє: СЌС‚Рѕ СѓР¶Рµ РЅРµ Р°РґСЂРµСЃ, Р° РїРѕРґРїРёСЃСЊ РґР»СЏ С‡РµР»РѕРІРµРєР°.
        if (value.Any(c => char.IsWhiteSpace(c) || c is '(' or ')' or ';' or '=')) return false;

        if (IPAddress.TryParse(value, out _)) return true;

        // Р”РѕРјРµРЅРЅРѕРµ РёРјСЏ: Р±СѓРєРІС‹/С†РёС„СЂС‹/РґРµС„РёСЃ/С‚РѕС‡РєРё, Р±РµР· РІРµРґСѓС‰РµРіРѕ/С…РІРѕСЃС‚РѕРІРѕРіРѕ РґРµС„РёСЃР°.
        if (!value.Contains('.')) return false;
        foreach (var label in value.Split('.'))
        {
            if (label.Length is 0 or > 63) return false;
            if (label.StartsWith('-') || label.EndsWith('-')) return false;
            if (label.Any(c => !char.IsLetterOrDigit(c) && c != '-')) return false;
        }

        return true;
    }
}




