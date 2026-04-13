#include <iostream>
#include <vector>
#include <filesystem>
#include <signal.h>
#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif
#include "ConsoleUtils.h"
#include "Menu.h"
#include "XrayLauncher.h"
#include "Settings.h"
#include "TrayIcon.h"
#include "mFile.h"

int main() {
    std::vector<Profile> profiles = {};
    Settings settings;
    int selected = 0;
    bool trayMode = false;
    bool xrayRunning = false;
    bool tunnelModeActive = false;   // legacy transparent-proxy tunnel
    bool tunModeActive    = false;   // real TUN virtual interface mode
    bool systemVpnActive  = false;
    bool netNsActive      = false;   // VPN network namespace is set up
    ProcessId activePid   = 0;
    std::string listenAddress;
    std::string activeLogFile;
    std::string activeTunIface;      // e.g. "utun5", "tun0"

    signal(SIGINT, SIG_IGN);
    loadSettings(settings);
    loadProfiles(profiles);
    loadAppList(settings);

    // Check if xray-core binary exists, offer to download if not
    std::string xrayBinaryPath = findXrayCoreBinary(settings);
    if (!std::filesystem::exists(xrayBinaryPath)) {
        clearScreen();
        std::cout << tr(settings.language, "Xray-core binary not found. Download Xray-core for your OS?", "Бинарник Xray-core не найден. Скачать Xray-core для вашей ОС?") << " (y/n): ";
        char choice = readKey();
        if (choice == 'y' || choice == 'Y') {
            if (downloadXrayCore(settings)) {
                std::cout << tr(settings.language, "Xray-core downloaded successfully.", "Xray-core успешно скачан.") << "\n";
            } else {
                std::cout << tr(settings.language, "Failed to download Xray-core.", "Не удалось скачать Xray-core.") << "\n";
            }
            pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        }
    }

    // Check for already running xray-core on startup
    XrayProcessInfo runningXray = findRunningXrayProcess();
    if (runningXray.pid > 0) {
        clearScreen();
        std::cout << "=== " << tr(settings.language, "Found running xray-core", "Обнаружен запущенный xray-core") << " ===\n\n";
        std::cout << tr(settings.language, "PID:", "PID:") << " " << runningXray.pid << "\n";
        std::cout << tr(settings.language, "Binary path:", "Путь бинарника:") << " " << runningXray.binaryPath << "\n";
        if (!runningXray.listenAddress.empty()) {
            std::cout << tr(settings.language, "Listening on:", "Слушает на:") << " " << runningXray.listenAddress << "\n";
        }
        std::cout << "\n" << tr(settings.language, "Use this process or start a new one?", "Использовать этот процесс или запустить новый?") << "\n";
        std::cout << "1. " << tr(settings.language, "Use running process", "Использовать запущенный процесс") << "\n";
        std::cout << "2. " << tr(settings.language, "Start new process", "Запустить новый процесс") << "\n";
        std::cout << tr(settings.language, "Press 1 or 2:", "Нажмите 1 или 2:") << " ";
        int choice = readKey();
        if (choice == '1') {
            activePid = runningXray.pid;
            xrayRunning = true;
            listenAddress = runningXray.listenAddress;
        }
    }

    hideCursor();
    bool logsEnabled = true;   // runtime toggle via tray context menu

    while (true) {
#ifndef _WIN32
        // ── Non-Windows: simple text-based "tray" ──────────────────────────
        if (trayMode) {
            clearScreen();
            std::cout << "=== " << mFile::APP_NAME << " ===\n";
            std::cout << tr(settings.language,
                "Application is minimized. Press Ctrl+F to restore.",
                "Приложение свёрнуто. Ctrl+F — восстановить.") << "\n";
            if (xrayRunning) {
                std::cout << tr(settings.language, "Port: ", "Порт: ")
                          << settings.proxyPort << "\n";
            }
            std::cout << tr(settings.language,
                "Press Ctrl+T to view xray-core logs.",
                "Нажмите Ctrl+T для просмотра логов xray-core.") << "\n";
            int key = readKey();
            if (key == 6) {
                trayMode = false;
            } else if (key == 20 && xrayRunning && !activeLogFile.empty() && logsEnabled) {
                trayMode = false;
                showXrayLog(activeLogFile, settings.language);
            }
            continue;
        }
#endif

        xrayRunning = (activePid != 0 && isXrayRunning(activePid));
        if (!xrayRunning) {
            activePid = 0;
        }

        clearScreen();
        std::cout << "=== " << mFile::APP_NAME << " " << mFile::APP_VERSION << " ===\n";
        std::cout << mFile::APP_DESCRIPTION << "\n";
        if (xrayRunning) {
            std::cout << tr(settings.language, "xray-core PID:", "PID xray-core:") << " " << activePid;
            if (tunModeActive) {
                std::cout << "  [TUN: " << activeTunIface << "  " << settings.tunnelSubnet << "]";
            } else if (tunnelModeActive) {
                std::cout << "  [" << tr(settings.language, "transparent proxy", "прозрачный прокси") << "]";
            } else {
                std::cout << "  [" << tr(settings.language, "proxy", "прокси") << ": " << listenAddress << "]";
            }
            if (settings.killSwitch && tunModeActive) {
                std::cout << "  [kill-switch]";
            }
            std::cout << "\n";
        }
        std::cout << "\n";
        std::cout << tr(settings.language, "Arrow keys / number + Enter to select.  Q = quit.  Ctrl+F = minimize.",
                                           "Стрелки / цифра + Enter для выбора.  Q = выход.  Ctrl+F = свернуть.") << "\n\n";

        std::vector<std::string> menuItems = {
            tr(settings.language, "Launch xray-core (proxy)", "Запустить xray-core (прокси)"),
            tr(settings.language, "Launch TUN tunnel (virtual interface)", "Запустить TUN туннель (виртуальный интерфейс)"),
            tr(settings.language, "Per-app proxy (route specific apps)", "Прокси для приложений (выбрать приложения)"),
            tr(settings.language, "Profiles", "Профили"),
            tr(settings.language, "Settings", "Настройки")
        };
        if (xrayRunning) {
            menuItems.push_back(tr(settings.language, "Show xray-core status", "Показать статус xray-core"));
            if (tunnelModeActive && !tunModeActive) {
                std::string vpnStatus = systemVpnActive ?
                    tr(settings.language, "Disable system VPN", "Отключить системный VPN") :
                    tr(settings.language, "Enable system VPN", "Включить системный VPN");
                menuItems.push_back(vpnStatus);
            }
            menuItems.push_back(tr(settings.language, "Stop xray-core", "Остановить xray-core"));
        }
        menuItems.push_back(tr(settings.language, "Exit", "Выход"));
        selected = std::min(selected, static_cast<int>(menuItems.size()) - 1);

        for (size_t i = 0; i < menuItems.size(); ++i) {
            std::cout << (static_cast<int>(i) == selected ? "> " : "  ");
            std::cout << i + 1 << ". " << menuItems[i] << "\n";
        }

        int key = readKey();
        if (key == 3) { // Ctrl+C
            continue; // ignore
        }
        if (key == 'q' || key == 'Q') { // q/Q — exit
            showCursor();
            clearScreen();
            if (netNsActive)     cleanupAppNetNS();
            if (systemVpnActive) cleanupSystemVPN(settings);
            if (tunModeActive)   cleanupTunVPN(settings);
            if (activePid > 0)   stopXrayCore(activePid);
            std::cout << tr(settings.language, "Exit...", "Выход...") << "\n";
            return 0;
        }
        if (key == 6) { // Ctrl+F — minimise to tray
#ifdef _WIN32
            TrayConfig trayCfg;
            trayCfg.port        = settings.proxyPort;
            trayCfg.xrayRunning = xrayRunning;
            trayCfg.logsEnabled = logsEnabled;
            trayCfg.language    = settings.language;
            trayCfg.logFile     = activeLogFile;
            TrayResult trayRes  = enterTrayMode(trayCfg);
            logsEnabled         = trayRes.logsEnabled;
            if (!trayRes.restore) {
                // User chose "Exit" from tray context menu
                showCursor();
                clearScreen();
                if (netNsActive)     cleanupAppNetNS();
                if (systemVpnActive) cleanupSystemVPN(settings);
                if (tunModeActive)   cleanupTunVPN(settings);
                if (activePid > 0)   stopXrayCore(activePid);
                std::cout << tr(settings.language, "Exit...", "Выход...") << "\n";
                return 0;
            }
            // Restored — fall through to normal menu loop
#else
            trayMode = true;
#endif
            continue;
        }
        if (key == 20) { // Ctrl+T
            if (xrayRunning && !activeLogFile.empty() && logsEnabled) {
                showXrayLog(activeLogFile, settings.language);
            }
            continue;
        }
        if (key == 1001) {
            selected = (selected - 1 + menuItems.size()) % menuItems.size();
        } else if (key == 1002) {
            selected = (selected + 1) % menuItems.size();
        } else if (key >= '1' && key <= '0' + static_cast<int>(menuItems.size())) {
            selected = key - '1';
            key = '\n';
        }

        if (key == '\n' || key == '\r') {
            std::string selectedItem = menuItems[selected];
            std::string launchStr    = tr(settings.language, "Launch xray-core (proxy)", "Запустить xray-core (прокси)");
            std::string tunLaunchStr = tr(settings.language, "Launch TUN tunnel (virtual interface)", "Запустить TUN туннель (виртуальный интерфейс)");
            std::string perAppStr    = tr(settings.language, "Per-app proxy (route specific apps)", "Прокси для приложений (выбрать приложения)");
            std::string profilesStr  = tr(settings.language, "Profiles", "Профили");
            std::string settingsStr  = tr(settings.language, "Settings", "Настройки");
            std::string statusStr    = tr(settings.language, "Show xray-core status", "Показать статус xray-core");
            std::string vpnEnableStr = tr(settings.language, "Enable system VPN", "Включить системный VPN");
            std::string vpnDisableStr= tr(settings.language, "Disable system VPN", "Отключить системный VPN");
            std::string stopStr      = tr(settings.language, "Stop xray-core", "Остановить xray-core");
            std::string exitStr      = tr(settings.language, "Exit", "Выход");

            // ── Helper: pick a profile by key press ───────────────────────────
            auto pickProfile = [&]() -> int {
                clearScreen();
                std::cout << tr(settings.language, "Select profile:", "Выберите профиль:") << "\n\n";
                for (size_t i = 0; i < profiles.size(); ++i) {
                    std::cout << i + 1 << ". " << profiles[i].name
                              << " (" << profiles[i].type << ") @ " << profiles[i].address << "\n";
                }
                std::cout << "\n" << tr(settings.language, "Press number key (1-9), or 0 to cancel: ", "Нажмите цифру (1-9) или 0 для отмены: ");
                int k = readKey();
                if (k >= '1' && k <= '0' + static_cast<int>(profiles.size())) return k - '1';
                return -1; // cancelled
            };

            if (selectedItem == launchStr) {
                // ── Proxy / transparent-proxy mode ────────────────────────────
                if (profiles.empty()) {
                    clearScreen();
                    std::cout << tr(settings.language, "No profiles available. Add profiles first.", "Нет доступных профилей. Сначала добавьте профили.") << "\n";
                    pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
                } else {
                    int idx = pickProfile();
                    if (idx >= 0) {
                        clearScreen();
                        std::cout << tr(settings.language, "Proxy protocol:", "Протокол прокси:") << "\n";
                        std::cout << "1. SOCKS5\n";
                        std::cout << "2. HTTP\n";
                        std::cout << tr(settings.language, "Press 1 or 2 (default SOCKS5): ", "Нажмите 1 или 2 (по умолч. SOCKS5): ");
                        int pk = readKey();
                        std::string proxyProtocol = (pk == '2') ? "http" : "socks";
                        if (launchXrayCore(settings, profiles[idx], false, proxyProtocol,
                                           activeLogFile, listenAddress, activePid)) {
                            xrayRunning      = true;
                            tunnelModeActive = false;
                            tunModeActive    = false;
                            systemVpnActive  = false;
                            showXrayLog(activeLogFile, settings.language);
                        }
                    }
                }
            } else if (selectedItem == tunLaunchStr) {
                // ── TUN virtual-interface mode ────────────────────────────────
                if (profiles.empty()) {
                    clearScreen();
                    std::cout << tr(settings.language, "No profiles available. Add profiles first.", "Нет доступных профилей. Сначала добавьте профили.") << "\n";
                    pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
                } else {
                    int idx = pickProfile();
                    if (idx >= 0) {
                        if (launchXrayTun(settings, profiles[idx],
                                          activeLogFile, activeTunIface, activePid)) {
                            xrayRunning      = true;
                            tunModeActive    = true;
                            tunnelModeActive = false;
                            systemVpnActive  = false;
                            listenAddress    = "127.0.0.1:" + std::to_string(settings.proxyPort);
                            showXrayLog(activeLogFile, settings.language);
                        }
                    }
                }
            } else if (selectedItem == perAppStr) {
                // ── Per-app proxy manager ──────────────────────────────────
                int activePort     = xrayRunning ? settings.proxyPort     : 0;
                int activeHttpPort = xrayRunning ? settings.httpProxyPort : 0;

                // Lambda: starts xray for per-app proxy.
                // For VPN namespace mode, xray must listen on 0.0.0.0 so the
                // namespace can reach it via the veth IP (10.200.0.1).
                // Called automatically when user hits Launch and proxy is off.
                auto startProxyForApp = [&](int& port, int& httpPort) -> bool {
                    if (profiles.empty()) {
                        clearScreen();
                        std::cout << tr(settings.language,
                            "No profiles — add one first in Profiles menu.",
                            "Нет профилей — сначала добавьте в меню Профили.") << "\n";
                        pauseScreen(tr(settings.language, "\nPress any key...", "\nЛюбая клавиша..."));
                        return false;
                    }
                    int idx = pickProfile();
                    if (idx < 0) return false;

                    // Stop previous xray if running (need to restart with netns config)
                    if (activePid > 0) {
                        stopXrayCore(activePid);
                        activePid   = 0;
                        xrayRunning = false;
                    }

                    std::string logF;
                    ProcessId pid = 0;
                    // Start xray listening on 0.0.0.0 (required for VPN netns mode)
                    if (!launchXrayCoreForNetNS(settings, profiles[idx], logF, pid))
                        return false;
                    activePid        = pid;
                    activeLogFile    = logF;
                    listenAddress    = "0.0.0.0:" + std::to_string(settings.proxyPort);
                    xrayRunning      = true;
                    tunnelModeActive = false;
                    tunModeActive    = false;
                    systemVpnActive  = false;

                    // Give xray a moment to start, then set up the namespace
                    usleep(800000);
                    if (isNetNSModeAvailable()) {
                        if (netNsActive) cleanupAppNetNS();
                        netNsActive = setupAppNetNS(settings.proxyPort, settings.language);
                    }

                    port     = settings.proxyPort;
                    httpPort = settings.httpProxyPort;
                    return true;
                };

                editAppProxyList(settings, profiles, startProxyForApp, activePort, activeHttpPort);
                saveAppList(settings);
            } else if (selectedItem == profilesStr) {
                editProfiles(profiles, settings.language);
                saveProfiles(profiles);
            } else if (selectedItem == settingsStr) {
                showCursor();
                editSettings(settings);
                saveSettings(settings);
                hideCursor();
            } else if (selectedItem == statusStr) {
                clearScreen();
                std::cout << "=== " << tr(settings.language, "xray-core status", "Статус xray-core") << " ===\n\n";
                std::cout << tr(settings.language, "PID:", "PID:") << " " << activePid << "\n";
                std::cout << tr(settings.language, "Log file:", "Файл лога:") << " " << activeLogFile << "\n";

                if (tunModeActive) {
                    std::cout << "\n" << tr(settings.language, "Mode: TUN tunnel (virtual interface)", "Режим: TUN туннель (виртуальный интерфейс)") << "\n";
                    std::cout << tr(settings.language, "Interface: ", "Интерфейс: ") << activeTunIface << "\n";
                    std::cout << tr(settings.language, "Subnet:    ", "Подсеть:    ") << settings.tunnelSubnet << "\n";
                    std::cout << tr(settings.language, "Kill-switch: ", "Kill-switch: ")
                              << (settings.killSwitch ? tr(settings.language, "ON", "ВКЛ") : tr(settings.language, "OFF", "ВЫКЛ")) << "\n";
                    std::cout << tr(settings.language, "Split-tunnel: ", "Split-tunnel: ")
                              << (settings.splitTunnel ? tr(settings.language, "ON", "ВКЛ") : tr(settings.language, "OFF", "ВЫКЛ")) << "\n";
                    if (settings.proxyPort > 0)
                        std::cout << "SOCKS5: 127.0.0.1:" << settings.proxyPort << "\n";
                    if (settings.httpProxyPort > 0)
                        std::cout << "HTTP:   127.0.0.1:" << settings.httpProxyPort << "\n";
#if defined(__linux__)
                    std::cout << "\n";
                    system("ip link show 2>/dev/null | grep 'tun' || true");
                    system("ip route show 2>/dev/null | head -6");
#elif defined(__APPLE__)
                    std::cout << "\n";
                    system("ifconfig 2>/dev/null | grep -A4 'utun' | head -20");
                    system("netstat -rn 2>/dev/null | head -12");
#endif
                } else if (tunnelModeActive) {
                    std::cout << "\n" << tr(settings.language, "Mode: transparent proxy (dokodemo-door)", "Режим: прозрачный прокси (dokodemo-door)") << "\n";
                    std::cout << tr(settings.language, "Listening on: ", "Слушает: ") << listenAddress << "\n";
                    if (systemVpnActive) {
                        std::cout << tr(settings.language, "System VPN: ON", "Системный VPN: ВКЛ") << "\n";
#ifdef __APPLE__
                        system("sudo pfctl -s rules 2>/dev/null | grep 'rdr' || echo '(no redirect rules)'");
#elif defined(__linux__)
                        system("sudo iptables -t nat -L OUTPUT --line-numbers 2>/dev/null | head -10");
#endif
                    } else {
                        std::cout << tr(settings.language, "System VPN: OFF (use 'Enable system VPN' to route all traffic)", "Системный VPN: ВЫКЛ (используйте 'Включить системный VPN' для маршрутизации всего трафика)") << "\n";
                    }
                } else {
                    std::cout << "\n" << tr(settings.language, "Mode: proxy", "Режим: прокси") << "\n";
                    std::cout << tr(settings.language, "Listening on: ", "Слушает: ") << listenAddress << "\n";
                }
                pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
            } else if (selectedItem == vpnEnableStr) {
                setupSystemVPN(settings, activePid);
                systemVpnActive = true;
            } else if (selectedItem == vpnDisableStr) {
                cleanupSystemVPN(settings);
                systemVpnActive = false;
            } else if (selectedItem == stopStr) {
                clearScreen();
                if (netNsActive) {
                    cleanupAppNetNS();
                    netNsActive = false;
                }
                if (systemVpnActive) {
                    cleanupSystemVPN(settings);
                    systemVpnActive = false;
                }
                if (tunModeActive) {
                    cleanupTunVPN(settings);
                    tunModeActive   = false;
                    activeTunIface.clear();
                }
                if (stopXrayCore(activePid)) {
                    std::cout << tr(settings.language, "xray-core stopped.", "xray-core остановлен.") << "\n";
                    activePid        = 0;
                    xrayRunning      = false;
                    tunnelModeActive = false;
                    listenAddress.clear();
                } else {
                    std::cout << tr(settings.language, "Failed to stop xray-core.", "Не удалось остановить xray-core.") << "\n";
                }
                pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
            } else if (selectedItem == exitStr) {
                showCursor();
                clearScreen();
                if (netNsActive)     cleanupAppNetNS();
                if (systemVpnActive) cleanupSystemVPN(settings);
                if (tunModeActive)   cleanupTunVPN(settings);
                if (activePid > 0)   stopXrayCore(activePid);
                std::cout << tr(settings.language, "Exit...", "Выход...") << "\n";
                return 0;
            }
        }
    }

    return 0;
}
