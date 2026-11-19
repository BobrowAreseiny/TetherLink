namespace ProxyBridge.Windows.Controls;

/// <summary>
/// Переключатель в стиле темы: светлый трек с тёмным колпачком во включённом состоянии
/// и тёмный трек со светлым колпачком — в выключенном.
///
/// Почему не встроенный Switch: его цвета задаются только OnColor и ThumbColor, а цвет
/// трека в выключенном состоянии платформенный. На тёмной теме это давало «белое на белом»
/// (Android) или невидимый колпачок — состояние не читалось.
/// </summary>
public sealed class PbToggle : ContentView
{
    private static readonly Color TrackOn = Color.FromArgb("#9FC9E0");
    private static readonly Color TrackOff = Color.FromArgb("#232B33");
    private static readonly Color KnobOn = Color.FromArgb("#0A0C0F");
    private static readonly Color KnobOff = Color.FromArgb("#7E8B96");
    private static readonly Color Stroke = Color.FromArgb("#232B33");

    private readonly Border _track;
    private readonly Border _knob;

    public static readonly BindableProperty IsToggledProperty = BindableProperty.Create(
        nameof(IsToggled),
        typeof(bool),
        typeof(PbToggle),
        false,
        BindingMode.TwoWay,
        propertyChanged: OnIsToggledChanged);

    public bool IsToggled
    {
        get => (bool)GetValue(IsToggledProperty);
        set => SetValue(IsToggledProperty, value);
    }

    public PbToggle()
    {
        _knob = new Border
        {
            WidthRequest = 22,
            HeightRequest = 22,
            StrokeThickness = 0,
            HorizontalOptions = LayoutOptions.Start,
            VerticalOptions = LayoutOptions.Center,
            Margin = new Thickness(4, 0, 0, 0),
        };

        _track = new Border
        {
            WidthRequest = 52,
            HeightRequest = 30,
            StrokeThickness = 1,
            Stroke = new SolidColorBrush(Stroke),
            Padding = 0,
            Content = new Grid { Children = { _knob } },
        };

        Content = _track;

        var tap = new TapGestureRecognizer();
        tap.Tapped += (_, _) => IsToggled = !IsToggled;
        _track.GestureRecognizers.Add(tap);

        Apply();
    }

    private static void OnIsToggledChanged(BindableObject bindable, object oldValue, object newValue)
        => ((PbToggle)bindable).Apply();

    private void Apply()
    {
        var on = IsToggled;

        _track.BackgroundColor = on ? TrackOn : TrackOff;
        _knob.BackgroundColor = on ? KnobOn : KnobOff;
        _knob.HorizontalOptions = on ? LayoutOptions.End : LayoutOptions.Start;
        _knob.Margin = on ? new Thickness(0, 0, 4, 0) : new Thickness(4, 0, 0, 0);

        // Доступность: состояние озвучивается скринридером
        SemanticProperties.SetHint(this, on ? "включено" : "выключено");
    }
}
