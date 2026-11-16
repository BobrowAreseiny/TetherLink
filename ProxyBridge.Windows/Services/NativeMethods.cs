using System.Runtime.InteropServices;

namespace ProxyBridge.Windows.Services;

/// <summary>Системные вызовы Windows, нужные для уведомления об изменении переменных окружения.</summary>
internal static class NativeMethods
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        string lParam,
        uint fuFlags,
        uint uTimeout,
        out IntPtr lpdwResult);
}
