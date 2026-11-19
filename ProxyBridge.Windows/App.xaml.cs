using ProxyBridge.Windows.Services;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using System.Runtime.InteropServices;
using System.Threading;
using WinRT.Interop;

namespace ProxyBridge.Windows;

public partial class App : Application
{
	private static readonly Mutex _singleInstanceMutex = new(false, "TetherLink.SingleInstance");

	public App()
	{
		// ЖЁСТКАЯ ПРОВЕРКА: приложение должно быть единственным экземпляром.
		// Если уже запущено — поднимаем существующее окно вперёд и выходим.
		var alreadyRunning = false;
		try
		{
			if (!_singleInstanceMutex.WaitOne(0))
				alreadyRunning = true;
		}
		catch (AbandonedMutexException)
		{
			// Прошлый экземпляр упал, не освободив мьютекс. Владение уже наше — продолжаем.
			System.Diagnostics.Debug.WriteLine("[ProxyBridge] Восстановлен брошенный мьютекс");
		}

		if (alreadyRunning)
		{
			BringExistingToFront();
			Environment.Exit(0);
			return;
		}

		InitializeComponent();
		UserAppTheme = AppTheme.Dark;

		// Переменные прокси могли остаться от прошлого запуска (жёсткий kill).
		// Тогда opencode/git стучались бы в адрес телефона, которого в сети нет.
		// Убираем их — при подключении выставим заново, уже с актуальным адресом.
		if (ProxyEnvironment.ClearOrphanedVariables())
		{
			ProxySession.AppendLog("Убраны переменные прокси от прошлого запуска");

			// Если OpenCode уже работает с этими мёртвыми переменными — закрываем сессию,
			// иначе он продолжит стучаться в пустоту до ручного перезапуска.
			OpencodeSession.TerminateIfRunning("очищены переменные от прошлого запуска");
		}

		// Аварийная уборка: процесс завершается — прокси, порт и adb forward откатываем.
		AppDomain.CurrentDomain.ProcessExit += (_, _) => ProxySession.CleanupBlocking();
		AppDomain.CurrentDomain.UnhandledException += (_, _) => ProxySession.CleanupBlocking();
	}

	private static void BringExistingToFront()
	{
		try
		{
			var hwnd = FindWindow(null, "TetherLink");
			if (hwnd != IntPtr.Zero)
			{
				ShowWindow(hwnd, 9); // SW_RESTORE
				SetForegroundWindow(hwnd);
			}
		}
		catch
		{
			// Игнорируем ошибки поиска окна — выйдем тихо.
		}
	}

	[DllImport("user32.dll")]
	private static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

	[DllImport("user32.dll")]
	private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

	[DllImport("user32.dll")]
	private static extern bool SetForegroundWindow(IntPtr hWnd);

	[DllImport("user32.dll", SetLastError = true)]
	private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter,
		int x, int y, int cx, int cy, uint uFlags);

	private static readonly IntPtr HwndNotTopmost = new(-2);
	private const uint SwpNoSize = 0x0001;
	private const uint SwpNoMove = 0x0002;
	private const uint SwpNoActivate = 0x0010;

	protected override Window CreateWindow(IActivationState? activationState)
	{
		var window = new Window(new MainPage())
		{
			Title = "TetherLink",
			// Узкое фиксированное окно: интерфейс рассчитан на одну колонку.
			// На 150% масштабирования 820 DIP превращались в 1230 px и низ окна
			// уезжал за край экрана, поэтому ширина и высота заданы явно.
			Width = 480,
			Height = 620
		};

		// Запрещаем растягивать окно мышью, разворачивать на весь экран и
		// прилипать к краям: интерфейс рассчитан на фиксированную ширину.
		window.HandlerChanged += (_, _) =>
		{
			if (window.Handler?.PlatformView is not Microsoft.UI.Xaml.Window nativeWindow) return;

			try
			{
				var hwnd = WindowNative.GetWindowHandle(nativeWindow);
				var windowId = Win32Interop.GetWindowIdFromWindow(hwnd);
				var appWindow = AppWindow.GetFromWindowId(windowId);

				if (appWindow.Presenter is OverlappedPresenter presenter)
				{
					presenter.IsResizable = false;
					presenter.IsMaximizable = false;
				}

				// Окно не должно быть «поверх всех»: активное окно (в том числе
				// OpenCode или проводник) должно перекрывать его обычным образом.
				// Снимаем WS_EX_TOPMOST на случай, если он остался от прошлой сессии.
				SetWindowPos(hwnd, HwndNotTopmost, 0, 0, 0, 0,
					SwpNoMove | SwpNoSize | SwpNoActivate);
			}
			catch (Exception ex)
			{
				System.Diagnostics.Debug.WriteLine($"[ProxyBridge] fixed window: {ex.Message}");
			}
		};

		// Закрытие окна крестиком — тоже полный откат.
		window.Destroying += (_, _) => ProxySession.CleanupBlocking();

		return window;
	}
}