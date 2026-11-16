using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Android.Content;
using Android.Net;

namespace ProxyBridge.Android.Services;

/// <summary>
/// Определяет IP-адрес интерфейса точки доступа (SoftAP) или USB-модема.
/// </summary>
internal static class HotspotIpResolver
{
    /// <summary>Однозначные имена интерфейсов точки доступа и USB-модема для всех брендов.</summary>
    private static readonly string[] UnambiguousApNames =
    [
        "ap0", "ap1", "ap2",
        "softap0", "softap1",
        "wlan_ap",
        "wifi_ap",
        "uap0", "ap_br0", "bridge0",       // MediaTek / Xiaomi / Huawei мосты
        "rndis0", "usb0", "ncm0", "ecm0"  // USB Tethering (раздача по кабелю)
    ];

    /// <summary>Имена, которые у Samsung/Pixel означают радио точки доступа (но не всегда).</summary>
    private static readonly string[] AmbiguousApNames = ["wlan1", "wlan2", "wlans0", "wlans1", "p2p-wlan0-0"];

    /// <summary>Мобильные и служебные интерфейсы — их адреса клиенту не нужны.</summary>
    private static readonly string[] ExcludedNameHints =
    [
        "rmnet", "ccmni", "pdp", "wwan", "cell", "gsm", "cdma", "lte", "nr_",
        "tunl", "ifb", "dummy", "erspan", "gre", "ip6_", "ip_", "sit", "p2p",
        "wifi-aware", "epdg", "vti", "tun", "ipsec", "ppp", "wg", "tap"
    ];

    /// <summary>
    /// Типовые подсети SoftAP и USB-модемов.
    /// </summary>
    private static readonly (string Network, int Prefix)[] HotspotNetworks =
    [
        ("192.168.43.0", 24),  // Android 11+, Samsung
        ("192.168.42.0", 24),  // USB Tethering / старые версии Android
        ("192.168.49.0", 24),  // часть прошивок (Samsung/OnePlus)
        ("192.168.122.0", 24), // часть Samsung/Huawei
        ("192.168.4.0", 24),   // некоторые прошивки
        ("192.168.168.0", 24), // LG/Samsung
        ("192.168.50.0", 24)   // Китайские OEM (Xiaomi/Realme)
    ];

    private sealed record InterfaceInfo(string Name, IPAddress Address, bool Excluded, bool UnambiguousApName, bool AmbiguousApName);

    private static bool LooksLikeSamsungOrVendorHotspot(InterfaceInfo info, List<InterfaceInfo> all)
    {
        // Проверяем спец-интерфейсы Samsung (swlan*) или USB-модемы (rndis/ncm)
        var isTargetName = info.Name.StartsWith("swlan", StringComparison.OrdinalIgnoreCase) ||
                           info.Name.StartsWith("rndis", StringComparison.OrdinalIgnoreCase) ||
                           info.Name.StartsWith("ncm", StringComparison.OrdinalIgnoreCase);

        if (!isTargetName) return false;

        var mobileIsWan = all.Any(i =>
            i.Name.StartsWith("rmnet", StringComparison.OrdinalIgnoreCase) ||
            i.Name.StartsWith("ccmni", StringComparison.OrdinalIgnoreCase));

        return mobileIsWan || InHotspotSubnet(info.Address) || IsPrivateIp(info.Address);
    }

    /// <summary>IP точки доступа или null, если точки доступа не включено.</summary>
    public static IPAddress? Resolve(Context? context)
    {
        try
        {
            var all = CollectDetailed();
            if (all.Count == 0) return null;

            // Если телефон сам подключен к интернету по Wi-Fi (репитер), отсекаем этот входной интерфейс
            var upstreamInterface = GetActiveInterfaceName(context);

            var candidates = all
                .Where(i => !string.Equals(i.Name, upstreamInterface, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // 1) безусловное имя точки доступа или USB-модема
            foreach (var i in candidates)
                if (i.UnambiguousApName)
                    return i.Address;

            // 2) точка доступа Samsung / USB: swlan* / rndis* вне зависимости от подсети
            foreach (var i in candidates)
                if (LooksLikeSamsungOrVendorHotspot(i, all))
                    return i.Address;

            var lan = candidates.Where(i => !i.Excluded).ToList();

            // 3) радио точки доступа — только если адрес в подсети SoftAP
            foreach (var i in lan)
                if (i.AmbiguousApName && InHotspotSubnet(i.Address))
                    return i.Address;

            // 4) любой интерфейс из типовых подсетей SoftAP
            foreach (var i in lan)
                if (InHotspotSubnet(i.Address))
                    return i.Address;

            // 5) ФОЛБЭК ДЛЯ СОВРЕМЕННОГО ANDROID (12+): 
            // Подсеть точки доступа теперь рандомизируется.
            // Ищем любой Wi-Fi или USB интерфейс, у которого есть приватный IP.
            foreach (var i in lan)
            {
                if (i.AmbiguousApName ||
                    i.Name.StartsWith("wlan", StringComparison.OrdinalIgnoreCase) ||
                    i.Name.StartsWith("ap", StringComparison.OrdinalIgnoreCase) ||
                    i.Name.StartsWith("swlan", StringComparison.OrdinalIgnoreCase) ||
                    i.Name.StartsWith("usb", StringComparison.OrdinalIgnoreCase) ||
                    i.Name.StartsWith("rndis", StringComparison.OrdinalIgnoreCase))
                {
                    if (IsPrivateIp(i.Address))
                        return i.Address;
                }
            }

            // 6) ничего не нашли — возвращаем null
            return null;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] HotspotIpResolver: {ex.Message}");
            return null;
        }
    }

    public static IPAddress? ResolveAdvertisedAddress(Context? context)
    {
        var hotspot = Resolve(context);
        if (hotspot is not null) return hotspot;

        try
        {
            var active = GetActiveInterfaceName(context);
            if (active is null) return null;

            var all = CollectDetailed();
            var match = all.FirstOrDefault(i =>
                !i.Excluded && string.Equals(i.Name, active, StringComparison.OrdinalIgnoreCase));

            return match?.Address;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] ResolveAdvertisedAddress: {ex.Message}");
            return null;
        }
    }

    public static bool InHotspotSubnet(IPAddress address)
    {
        foreach (var (network, prefix) in HotspotNetworks)
        {
            var net = IPAddress.Parse(network);
            if (IsInSubnet(address, net, prefix))
                return true;
        }
        return false;
    }

    public static string? GetActiveInterfaceName(Context? context)
    {
        try
        {
            if (context is null) return null;

            var manager = (ConnectivityManager?)context.GetSystemService(Context.ConnectivityService);
            var network = manager?.ActiveNetwork;
            if (network is null) return null;

            return manager?.GetLinkProperties(network)?.InterfaceName;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] GetActiveInterfaceName: {ex.Message}");
            return null;
        }
    }

    public static IReadOnlyList<(string Name, IPAddress Address)> Collect()
        => CollectDetailed().Select(i => (i.Name, i.Address)).ToList();

    private static List<InterfaceInfo> CollectDetailed()
    {
        var result = new List<InterfaceInfo>();

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var lower = ni.Name.ToLowerInvariant();
                var excluded = ExcludedNameHints.Any(hint => lower.Contains(hint, StringComparison.Ordinal));

                foreach (var unicast in ni.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(unicast.Address)) continue;

                    result.Add(new InterfaceInfo(
                        ni.Name,
                        unicast.Address,
                        excluded,
                        UnambiguousApNames.Contains(ni.Name, StringComparer.OrdinalIgnoreCase) || lower.StartsWith("rndis", StringComparison.Ordinal),
                        AmbiguousApNames.Contains(ni.Name, StringComparer.OrdinalIgnoreCase)));
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ProxyBridge] CollectDetailed: {ex.Message}");
        }

        return result;
    }

    public static bool IsHotspotInterfacePresent()
        => CollectDetailed().Any(i => i.UnambiguousApName);

    private static bool IsInSubnet(IPAddress address, IPAddress network, int prefix)
    {
        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;

        for (var i = 0; i < fullBytes; i++)
            if (a[i] != n[i]) return false;

        if (remainingBits == 0) return true;

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (a[fullBytes] & mask) == (n[fullBytes] & mask);
    }

    private static bool IsPrivateIp(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168);
    }
}