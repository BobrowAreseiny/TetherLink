using ProxyBridge.Windows.Services;
using System.Runtime.InteropServices;
using System.Threading;

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
			ProxySession.AppendLog("Убраны переменные прокси от прошлого запуска");

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

	protected override Window CreateWindow(IActivationState? activationState)
	{
		var window = new Window(new MainPage())
		{
			Title = "TetherLink",
			// Окно должно целиком влезать в экран ноутбука: на 150% масштабирования
			// 820 DIP превращались в 1230 px и низ окна уезжал за край экрана.
			Width = 600,
			Height = 620
		};

		// Закрытие окна крестиком — тоже полный откат.
		window.Destroying += (_, _) => ProxySession.CleanupBlocking();

		return window;
	}
}