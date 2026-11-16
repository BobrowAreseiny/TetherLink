using ProxyBridge.Android.ViewModels;

namespace ProxyBridge.Android;

public partial class MainPage : ContentPage
{
	private readonly ProxyViewModel _viewModel = new();

	public MainPage()
	{
		InitializeComponent();
		BindingContext = _viewModel;
	}

	protected override void OnAppearing()
	{
		base.OnAppearing();
		_viewModel.Refresh();
		_viewModel.StartUiTimer();
	}

	protected override void OnDisappearing()
	{
		base.OnDisappearing();
		_viewModel.StopUiTimer();
	}
}