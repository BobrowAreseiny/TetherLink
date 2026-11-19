using Microsoft.Extensions.Logging;

namespace ProxyBridge.Windows;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp()
	{
		var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
				fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
			});

		// Поле ввода рисуем сами (квадратная рамка Border), поэтому убираем
		// родную рамку, фон и скругление WinUI-TextBox — иначе внутри виден второй прямоугольник.
		// Всё в try/catch: косметика не должна ронять приложение.
		Microsoft.Maui.Handlers.EntryHandler.Mapper.AppendToMapping("PbFlatEntry", (handler, view) =>
		{
			try
			{
				handler.PlatformView.BorderThickness = new Microsoft.UI.Xaml.Thickness(0);
				handler.PlatformView.CornerRadius = new Microsoft.UI.Xaml.CornerRadius(0);
				handler.PlatformView.BorderBrush = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Transparent);
				handler.PlatformView.Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Transparent);
				handler.PlatformView.Padding = new Microsoft.UI.Xaml.Thickness(0, 4, 0, 4);
				handler.PlatformView.UseSystemFocusVisuals = false;
				handler.PlatformView.FocusVisualPrimaryThickness = new Microsoft.UI.Xaml.Thickness(0);
				handler.PlatformView.FocusVisualSecondaryThickness = new Microsoft.UI.Xaml.Thickness(0);
			}
			catch (Exception ex)
			{
				System.Diagnostics.Debug.WriteLine($"[ProxyBridge] Entry chrome: {ex.Message}");
			}
		});

#if DEBUG
		builder.Logging.AddDebug();
#endif

		return builder.Build();
	}
}
