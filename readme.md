# vL2

Консольный клиент для xray-core с поддержкой множества подключений и фильтрацией трафика по сайтам и приложениям.

## Возможности

- 📡 Управление несколькими профилями подключений (VMess, VLESS, Trojan, Shadowsocks)
- 🔍 Фильтрация трафика по доменам (allow/block/proxy)
- 🎯 Фильтрация по процессам/приложениям (например, Telegram, Discord)
- 🖥️ TUI (Terminal User Interface) для удобного управления
- ⚡ Быстрое переключение между профилями
- 📊 Логи в реальном времени
- 🔧 Работа через xray-core

## Установка

### Предварительные требования

- Go 1.21+
- xray-core (устанавливается автоматически)

### Из исходников

```bash
[git clone https://github.com/lackyhy/vL2.git
cd vl2
make build
```

### Сборка C++ основы

Linux/macOS:

```bash
g++ main.cpp -o vl2 -std=c++17
./vl2
```

Windows (MSVC):

```powershell
cl /EHsc main.cpp /Fe:vl2.exe
vl2.exe
```

Windows (MinGW):

```bash
g++ main.cpp -o vl2.exe -std=c++17
vl2.exe
```

### CMake сборка

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

### Использование xray-core из папки

<!-- Положите исполняемый файл `xray-core` (или `xray-core.exe` на Windows) в папку `./xray-core`. -->

В приложении в меню `Настройки` можно указать путь к папке `xray-core`, а также выбрать язык.
По умолчанию интерфейс запускается на английском.

<!--
> В этой версии реализовано меню с выбором стрелками и цифрами, разделы `Профили` и `Настройки`, а также выбор языка и папки xray-core. -->
