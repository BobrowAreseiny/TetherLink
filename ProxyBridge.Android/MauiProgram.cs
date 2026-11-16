using Microsoft.Extensions.Logging;

namespace ProxyBridge.Android;

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

		// Поле ввода рисуем сами (скруглённая «капсула» в Border), поэтому убираем
		// у родного EditText фон и подчёркивание — иначе они просвечивают внутри капсулы.
		Microsoft.Maui.Handlers.EntryHandler.Mapper.AppendToMapping("PbFlatEntry", (handler, view) =>
		{
			handler.PlatformView.BackgroundTintList =
				global::Android.Content.Res.ColorStateList.ValueOf(global::Android.Graphics.Color.Transparent);
			handler.PlatformView.SetBackgroundColor(global::Android.Graphics.Color.Transparent);
		});

#if DEBUG
		builder.Logging.AddDebug();
#endif

		return builder.Build();
	}
}
