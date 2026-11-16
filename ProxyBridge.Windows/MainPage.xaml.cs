using ProxyBridge.Windows.ViewModels;

namespace ProxyBridge.Windows;

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
	}
}