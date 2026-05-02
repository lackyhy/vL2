# vL2 \

Console client for xray-core with support for multiple connections and traffic filtering by sites and applications.

## Features

- Multiple connection profiles (VMess, VLESS, Trojan, Shadowsocks)
- Domain-based traffic filtering (allow / block / proxy)
- Per-process / per-application routing (Telegram, Discord, etc.)
- TUI (Terminal User Interface) with arrow-key navigation
- Fast profile switching
- Real-time logs
- Optional SOCKS5 local authentication
- Powered by xray-core

## Requirements

- xray-core binary (placed in `./xray/` or configured via Settings)
- CMake 3.10+
- C++17 compiler (g++ / clang++)

## Build

<details>
<summary>macOS</summary>

**Prerequisites:** Xcode Command Line Tools and optionally Homebrew.

```bash
# Install cmake if missing
brew install cmake

# Build
./build.sh
```

Or manually:

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j$(sysctl -n hw.ncpu)
```

The binary is placed at `build/vl2`.

</details>

<details>
<summary>Linux (Debian / Ubuntu)</summary>

```bash
sudo apt-get update
sudo apt-get install -y cmake g++ make

./build.sh
```

Or manually:

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j$(nproc)
```

</details>

<details>
<summary>Arch Linux</summary>

```bash
sudo pacman -Sy --needed cmake gcc make

./build.sh
```

Or manually:

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j$(nproc)
```

</details>

<details>
<summary>Linux (Fedora / RHEL)</summary>

```bash
sudo dnf install -y cmake gcc-c++ make

./build.sh
```

</details>

<details>
<summary>Windows (MSVC)</summary>

```powershell
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

</details>

<details>
<summary>Windows (MinGW / MSYS2)</summary>

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -G "MinGW Makefiles"
cmake --build build -- -j4
```

MinGW builds statically link the C++ runtime — no extra DLLs needed.

</details>

## Embedding xray-core (optional)

Place the xray binary in `./xray/xray` (macOS/Linux) or `./xray/xray.exe` (Windows) before running CMake.  
If found, the binary is embedded directly into the vl2 executable via `.incbin` (GCC / Clang only).  
Without embedding, vl2 searches for xray at runtime using the path configured in Settings.

## Usage

```bash
./build/vl2
```

Navigate with arrow keys or number keys. Press `Q` to quit, `Ctrl+F` to minimize, `Ctrl+T` to view xray-core logs.

In the **Settings** menu (option 4 from the main menu) you can configure:

- SOCKS5 / HTTP proxy ports
- SOCKS5 local authentication (username + password)
- DNS servers
- TUN interface, kill-switch, split-tunnel
- xray-core folder path
- Language (EN / RU)

## License

See [LICENSE](LICENSE).
