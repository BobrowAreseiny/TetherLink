using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using ProxyBridge.Android.Services;

namespace ProxyBridge.Android;

[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, LaunchMode = LaunchMode.SingleTop, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
	/// <summary>
	/// Пользователь закрыл приложение — гасим foreground-сервис, чтобы освободить порт.
	/// IsFinishing = true только при реальном закрытии (не при повороте экрана).
	/// </summary>
	protected override void OnDestroy()
	{
		if (IsFinishing)
			ProxyForegroundService.RequestStop(this);

		base.OnDestroy();
	}
}