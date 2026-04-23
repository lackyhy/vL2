#!/usr/bin/env bash
set -e

# ── vL2 build script (macOS / Linux / Arch Linux) ────────────────────────────

OS="$(uname -s)"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
BUILD_DIR="build"

have() { command -v "$1" >/dev/null 2>&1; }

install_deps_arch() {
    echo "[*] Arch Linux detected — checking dependencies..."
    local pkgs=()
    have cmake || pkgs+=(cmake)
    have g++   || pkgs+=(gcc)
    have make  || pkgs+=(make)
    if [ ${#pkgs[@]} -gt 0 ]; then
        echo "[*] Installing: ${pkgs[*]}"
        sudo pacman -Sy --needed --noconfirm "${pkgs[@]}"
    fi
}

install_deps_debian() {
    echo "[*] Debian/Ubuntu detected — checking dependencies..."
    local pkgs=()
    have cmake || pkgs+=(cmake)
    have g++   || pkgs+=(g++)
    have make  || pkgs+=(make)
    if [ ${#pkgs[@]} -gt 0 ]; then
        echo "[*] Installing: ${pkgs[*]}"
        sudo apt-get update -qq
        sudo apt-get install -y "${pkgs[@]}"
    fi
}

install_deps_fedora() {
    echo "[*] Fedora/RHEL detected — checking dependencies..."
    local pkgs=()
    have cmake || pkgs+=(cmake)
    have g++   || pkgs+=(gcc-c++)
    have make  || pkgs+=(make)
    if [ ${#pkgs[@]} -gt 0 ]; then
        echo "[*] Installing: ${pkgs[*]}"
        sudo dnf install -y "${pkgs[@]}"
    fi
}

install_deps_macos() {
    echo "[*] macOS detected — checking dependencies..."
    if ! have cmake; then
        if have brew; then
            echo "[*] Installing cmake via Homebrew..."
            brew install cmake
        else
            echo "[!] cmake not found. Install it:"
            echo "    brew install cmake"
            echo "    or download from https://cmake.org/download/"
            exit 1
        fi
    fi
    # Xcode Command Line Tools provide clang / clang++
    if ! have clang++; then
        echo "[*] Installing Xcode Command Line Tools..."
        xcode-select --install || true
    fi
}

# ── Detect distro and install deps ───────────────────────────────────────────
case "$OS" in
    Linux)
        if have pacman; then
            install_deps_arch
        elif have apt-get; then
            install_deps_debian
        elif have dnf; then
            install_deps_fedora
        elif have yum; then
            echo "[*] yum-based distro — checking dependencies..."
            have cmake || sudo yum install -y cmake
            have g++   || sudo yum install -y gcc-c++
            have make  || sudo yum install -y make
        else
            echo "[!] Unknown Linux distro. Make sure cmake and g++ are installed."
        fi
        ;;
    Darwin)
        install_deps_macos
        ;;
    *)
        echo "[!] Unsupported OS: $OS"
        exit 1
        ;;
esac

# ── Build ─────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Configuring with CMake..."
mkdir -p "$BUILD_DIR"
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release

echo ""
echo "[*] Building with $JOBS jobs..."
cmake --build "$BUILD_DIR" -- -j"$JOBS"

echo ""
echo "[+] Build complete: $(realpath "$BUILD_DIR/vl2" 2>/dev/null || echo "$PWD/$BUILD_DIR/vl2")"
