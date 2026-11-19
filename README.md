# TetherLink

Прокси-сервер для раздачи интернета с телефона на ноутбук через точку доступа Wi-Fi.

Телефон поднимает SOCKS5/HTTP-прокси в сети точки доступа, ноутбук подключается к нему и получает доступ в интернет через мобильную сеть телефона. Системный прокси Windows настраивается автоматически — браузеры, git, npm, docker работают сразу.

## Возможности

- **Прокси на телефоне**: HTTP CONNECT и SOCKS5 (включая UDP ASSOCIATE)
- **Автоматическое обнаружение**: ноутбук сам находит IP телефона в сети точки доступа
- **Системная интеграция Windows**: автоматическая настройка прокси в реестре + переменные окружения для CLI-утилит
- **Автовосстановление**: при обрыве связи ноутбук сам переподключается
- **Маскировка трафика**: TTL=64, фильтрация телеметрии Windows, мобильный User-Agent
- **Энергосбережение**: Wi-Fi lock + адаптивный wake lock, исключение из оптимизации батареи

## Архитектура

**Ядро** (`ProxyBridge.Core`): платформенно-независимый код — TcpListener, HTTP/SOCKS5 хендлеры, PAC-сервер, счётчики трафика.

**Android** (`ProxyBridge.Android`): foreground-сервис с wake lock, определение IP точки доступа, UI на .NET MAUI.

**Windows** (`ProxyBridge.Windows`): поиск телефона в сети, настройка системного прокси и переменных окружения, UI на WinUI 3.

## Установка

### Android

Скачайте APK из [Releases](../../releases) или соберите из исходников:

```bash
dotnet build ProxyBridge.Android -c Release
adb install ProxyBridge.Android/bin/Release/net10.0-android/com.example.proxybridge-Signed.apk
```

Требования: Android 8.0+ (API 26).

### Windows

Скачайте архив из [Releases](../../releases) и распакуйте в любое место. Запустите `ProxyBridge.Windows.exe`. Установка не требуется.

Требования: Windows 10 19041+.

## Использование

### 1. На телефоне

1. Включите точку доступа: **Настройки → Сеть и интернет → Точка доступа Wi-Fi**
2. Откройте TetherLink, нажмите большую кнопку по центру
3. Разрешите уведомления (Android 13+)
4. Запомните адрес из карточки статуса (например, `192.168.43.1:9000`)

### 2. На ноутбуке

1. Подключитесь к точке доступа телефона по Wi-Fi
2. Запустите TetherLink на ноутбуке
3. Приложение само найдёт телефон и предложит подключиться
4. Нажмите **«Подключить»**

После подключения:
- Браузеры (Chrome, Edge, Firefox) работают через прокси автоматически
- Для CLI-утилит (git, npm, docker) переменные окружения применяются к новым процессам — перезапустите терминал

### 3. Проверка

```bash
# Внешний IP должен совпадать с мобильным IP телефона
curl https://ifconfig.me
```

### 4. Отключение

На ноутбуке: нажмите **«Отключить»** или закройте окно. Системный прокси и переменные окружения откатятся автоматически.

На телефоне: нажмите кнопку ещё раз или свайпните приложение из списка задач.

## Сборка из исходников

### Требования

- .NET SDK 10.0+
- Android SDK 36, JDK 21 (для Android-сборки)
- Windows SDK 10.0.19041+ (для Windows-сборки)

### Команды

```bash
# Сборка всего решения
dotnet build ProxyBridge.slnx

# Сборка Android APK
dotnet build ProxyBridge.Android -c Release
# APK: ProxyBridge.Android/bin/Release/net10.0-android/com.example.proxybridge-Signed.apk

# Сборка Windows (self-contained)
dotnet publish ProxyBridge.Windows -c Release -r win-x64 --self-contained
# EXE: ProxyBridge.Windows/bin/Release/net10.0-windows10.0.19041.0/win-x64/ProxyBridge.Windows.exe
```

### Структура репозитория

```
ProxyBridge/
├── ProxyBridge.Core/          # Ядро: прокси-сервер, протоколы, PAC
├── ProxyBridge.Android/       # Android-приложение (foreground-сервис)
├── ProxyBridge.Windows/       # Windows-приложение (WinUI 3)
├── tools/
│   ├── CoreSmokeTest/         # Интеграционные тесты ядра
│   └── ProbeTest/             # Проверка работоспособности прокси
└── artifacts/                 # Готовые сборки
    ├── android-release/
    └── win-release-new/
```

## Лицензия

MIT
