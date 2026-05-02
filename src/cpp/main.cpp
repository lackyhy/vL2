#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <signal.h>
#include <string>
#include <algorithm>
#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#include "ConsoleUtils.h"
#include "Menu.h"
#include "XrayLauncher.h"
#include "Settings.h"
#include "TrayIcon.h"
#include "mFile.h"

// Set to true when running in headless CLI mode — suppresses TUI output
// inside launcher functions (clearScreen, pauseScreen, progress prints).
bool g_headlessMode = false;

// ── CLI argument parsing ───────────────────────────────────────────────────

enum class CliAction {
    None,           // no action → show TUI
    Socks5,         // --socks5
    Http,           // --http
    Tun,            // --tun
    Stop,           // --stop
    Status,         // --status
    ListProfiles,   // --list-profiles
    Download,       // --download
};

struct CliArgs {
    CliAction action  = CliAction::None;
    std::string profile;   // profile name or 1-based index
    int  port         = 0; // custom listen port (0 = use settings)
    bool second       = false; // use second proxy slot
    bool showLog      = true;  // print xray log path on start
};

static CliArgs parseArgs(int argc, char** argv) {
    CliArgs a;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--socks5" || arg == "-s")           { a.action = CliAction::Socks5; }
        else if (arg == "--http"    || arg == "-H")      { a.action = CliAction::Http; }
        else if (arg == "--tun"     || arg == "-t")      { a.action = CliAction::Tun; }
        else if (arg == "--stop"    || arg == "-x")      { a.action = CliAction::Stop; }
        else if (arg == "--status"  || arg == "-S")      { a.action = CliAction::Status; }
        else if (arg == "--list-profiles" || arg == "-l"){ a.action = CliAction::ListProfiles; }
        else if (arg == "--download"|| arg == "-d")      { a.action = CliAction::Download; }
        else if (arg == "--second"  || arg == "-2")      { a.second = true; }
        else if (arg == "--no-log"  || arg == "-n")      { a.showLog = false; }
        else if ((arg == "--profile" || arg == "-p") && i + 1 < argc) {
            a.profile = argv[++i];
        } else if ((arg == "--port" || arg == "-P") && i + 1 < argc) {
            try { a.port = std::stoi(argv[++i]); } catch (...) {}
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "vl2 <3\n\n"
                      << "Usage: vl2 [OPTIONS]\n\n"
                      << "  (no args)                      Interactive TUI\n\n"
                      << "Actions:\n"
                      << "  --socks5,  -s                  Launch SOCKS5 proxy (headless)\n"
                      << "  --http,    -H                  Launch HTTP proxy  (headless)\n"
                      << "  --tun,     -t                  Launch TUN tunnel  (headless)\n"
                      << "  --stop,    -x                  Stop running xray-core and exit\n"
                      << "  --status,  -S                  Show xray-core status and exit\n"
                      << "  --list-profiles, -l            List saved profiles and exit\n"
                      << "  --download, -d                 Download xray-core binary and exit\n\n"
                      << "Options:\n"
                      << "  --profile <name|N>, -p         Profile name or 1-based index\n"
                      << "  --port <port>,      -P         Custom listen port\n"
                      << "  --second,           -2         Use second proxy slot\n"
                      << "  --no-log,           -n         Don't print log file path on start\n\n"
                      << "Examples:\n"
                      << "  vl2 -s -p MyVPN\n"
                      << "  vl2 -H -p 2 -P 8080\n"
                      << "  vl2 -t -p MyVPN\n"
                      << "  vl2 -s -2 -p 2 -P 1081\n"
                      << "  vl2 -x\n"
                      << "  vl2 -l\n\n"
                      << "tip: vl2 -s  launches first profile as socks5 right away ;)\n";
            exit(0);
        } else {
            std::cerr << "unknown argument: " << arg << "     404 <3 \n"
                      << "Try 'vl2 --help' to see available options.\n";
            exit(1);
        }
    }
    return a;
}

// Resolve profile by name or 1-based index string. Returns index or -1.
static int resolveProfile(const std::vector<Profile>& profiles, const std::string& spec) {
    if (spec.empty()) return profiles.empty() ? -1 : 0;
    // Try numeric index
    try {
        int idx = std::stoi(spec) - 1;
        if (idx >= 0 && idx < static_cast<int>(profiles.size())) return idx;
    } catch (...) {}
    // Try name match (case-insensitive substring)
    std::string lower = spec;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (int i = 0; i < static_cast<int>(profiles.size()); ++i) {
        std::string n = profiles[i].name;
        std::transform(n.begin(), n.end(), n.begin(), ::tolower);
        if (n.find(lower) != std::string::npos) return i;
    }
    return -1;
}

static const char* VL2_PID_FILE = "vl2.pid";

static void writePidFile(ProcessId pid, const std::string& listenAddr) {
    std::ofstream f(VL2_PID_FILE);
    if (f) f << pid << "\n" << listenAddr << "\n";
}

static ProcessId readPidFile(std::string* outListen = nullptr) {
    std::ifstream f(VL2_PID_FILE);
    if (!f) return 0;
    long pid = 0;
    f >> pid;
    if (outListen) { std::getline(f, *outListen); std::getline(f, *outListen); }
    return static_cast<ProcessId>(pid);
}

static void removePidFile() {
    std::remove(VL2_PID_FILE);
}

// ── Headless proxy runner ──────────────────────────────────────────────────
// Launches proxy, prints status, and exits — xray keeps running in background.
static int runHeadless(const CliArgs& a, Settings& settings, std::vector<Profile>& profiles) {
    g_headlessMode = true;
    // No --profile given → auto-pick first profile ;)
    int profileIdx = resolveProfile(profiles, a.profile);
    if (profileIdx < 0) {
        std::cerr << "404 <3  no profiles found";
        if (!a.profile.empty()) std::cerr << " matching '" << a.profile << "'";
        std::cerr << ". Add profiles first (run without args).\n";
        return 1;
    }

    std::cout << "[vl2] profile: " << profiles[profileIdx].name
              << " (" << profiles[profileIdx].type << ") ;)\n";

    // Override port if given
    if (a.port > 0) {
        if (a.second) settings.proxy2Port = a.port;
        else          settings.proxyPort  = a.port;
    }

    std::string logFile, listenAddr;
    ProcessId pid = 0;
    bool ok = false;

    if (a.action == CliAction::Tun) {
        std::string tunIface;
        ok = launchXrayTun(settings, profiles[profileIdx], logFile, tunIface, pid);
        if (ok) {
            listenAddr = tunIface;
            std::cout << "[vl2] TUN tunnel started  PID=" << pid
                      << "  iface=" << tunIface << "  <3\n";
        }
    } else {
        std::string proto = (a.action == CliAction::Http) ? "http" : "socks";
        int instanceId    = a.second ? 2 : 1;
        ok = launchXrayCore(settings, profiles[profileIdx], false, proto,
                            logFile, listenAddr, pid, instanceId);
        if (ok) {
            std::cout << "[vl2] " << (proto == "http" ? "HTTP" : "SOCKS5")
                      << " proxy started  PID=" << pid
                      << "  listen=" << listenAddr << "  <3\n";
        }
    }

    if (!ok) {
        std::cerr << "[vl2] failed to launch xray-core :(\n";
        return 1;
    }
    writePidFile(pid, listenAddr);
    if (a.showLog && !logFile.empty()) {
        std::cout << "[vl2] log: " << logFile << "\n";
    }
    std::cout << "[vl2] to stop: vl2 --stop\n";
    return 0;
}

int main(int argc, char** argv) {
    CliArgs cliArgs = parseArgs(argc, argv);
    std::vector<Profile> profiles = {};
    Settings settings;
    int selected = 0;
#ifndef _WIN32
    bool trayMode = false;
#endif
    bool xrayRunning = false;
    bool tunnelModeActive = false;   // legacy transparent-proxy tunnel
    bool tunModeActive    = false;   // real TUN virtual interface mode
    bool systemVpnActive  = false;
    bool netNsActive      = false;   // VPN network namespace is set up
#ifdef _WIN32
    bool winProxyActive   = false;   // Windows system (WinInet) proxy
#endif
    ProcessId activePid   = 0;
    std::string listenAddress;
    std::string activeLogFile;
    std::string activeAccessLogFile; // xray access log (per-connection routing events)
    std::string activeTunIface;      // e.g. "utun5", "tun0"

    // ── Second proxy instance ─────────────────────────────────────────────────
    bool xrayRunning2      = false;
    ProcessId activePid2   = 0;
    std::string listenAddress2;
    std::string activeLogFile2;

    signal(SIGINT, SIG_IGN);
    loadSettings(settings);
    loadProfiles(profiles);
    loadAppList(settings);

    // ── Handle CLI-only actions (no TUI) ──────────────────────────────────────
    if (cliArgs.action == CliAction::ListProfiles) {
        if (profiles.empty()) {
            std::cout << "no profiles saved :( run without args to add some.\n";
            return 0;
        }
        std::cout << "profiles <3\n";
        for (size_t i = 0; i < profiles.size(); ++i) {
            std::cout << "  " << i + 1 << ". " << profiles[i].name
                      << "  (" << profiles[i].type << ")  " << profiles[i].address << "\n";
        }
        return 0;
    }

    if (cliArgs.action == CliAction::Download) {
        std::cout << "[vl2] Downloading xray-core...\n";
        return downloadXrayCore(settings) ? 0 : 1;
    }

    if (cliArgs.action == CliAction::Stop) {
        // Prefer PID file written by headless launch (most reliable)
        ProcessId pid = readPidFile();
        if (pid <= 0) {
            XrayProcessInfo info = findRunningXrayProcess();
            pid = info.pid;
        }
        if (pid <= 0) {
            std::cout << "[vl2] no running xray-core found :|\n";
            return 0;
        }
        std::cout << "[vl2] stopping xray-core PID=" << pid << "...\n";
        bool ok = stopXrayCore(pid);
        if (ok) { removePidFile(); std::cout << "[vl2] stopped. o7\n"; }
        return ok ? 0 : 1;
    }

    if (cliArgs.action == CliAction::Status) {
        std::string listenAddr;
        ProcessId pid = readPidFile(&listenAddr);
        if (pid > 0 && isXrayRunning(pid)) {
            std::cout << "[vl2] running <3\n"
                      << "  PID:    " << pid << "\n";
            if (!listenAddr.empty())
                std::cout << "  listen: " << listenAddr << "\n";
            return 0;
        }
        // Fallback: scan processes
        XrayProcessInfo info = findRunningXrayProcess();
        if (info.pid <= 0) {
            std::cout << "[vl2] not running :|\n";
            return 0;
        }
        std::cout << "[vl2] running <3\n"
                  << "  PID:    " << info.pid << "\n"
                  << "  binary: " << info.binaryPath << "\n";
        if (!info.listenAddress.empty())
            std::cout << "  listen: " << info.listenAddress << "\n";
        return 0;
    }

    if (cliArgs.action == CliAction::Socks5 ||
        cliArgs.action == CliAction::Http   ||
        cliArgs.action == CliAction::Tun) {
        return runHeadless(cliArgs, settings, profiles);
    }

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

    // Check for already running xray-core on startup.
    // First check vl2.pid (written by headless launch), then scan processes.
    {
        std::string pidListen;
        ProcessId pidFromFile = readPidFile(&pidListen);
        XrayProcessInfo runningXray;
        if (pidFromFile > 0 && isXrayRunning(pidFromFile)) {
            runningXray.pid          = pidFromFile;
            runningXray.listenAddress = pidListen;
            runningXray.binaryPath   = "(headless launch)";
        } else {
            if (pidFromFile > 0) removePidFile(); // stale pid file
            runningXray = findRunningXrayProcess();
        }

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
                activePid     = runningXray.pid;
                xrayRunning   = true;
                listenAddress = runningXray.listenAddress;
            }
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
        xrayRunning2 = (activePid2 != 0 && isXrayRunning(activePid2));
        if (!xrayRunning2) {
            activePid2 = 0;
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
        if (xrayRunning2) {
            std::cout << tr(settings.language, "xray-core #2 PID:", "PID xray-core #2:") << " " << activePid2
                      << "  [" << tr(settings.language, "proxy", "прокси") << ": " << listenAddress2 << "]\n";
        }
        std::cout << "\n";
        std::cout << tr(settings.language,
            "Arrow keys / number + Enter to select.  Q = quit.  Ctrl+F = minimize.  L = traffic log.",
            "Стрелки / цифра + Enter для выбора.  Q = выход.  Ctrl+F = свернуть.  L = лог трафика.") << "\n\n";

        std::vector<std::string> menuItems = {
            tr(settings.language, "Launch xray-core (proxy)", "Запустить xray-core (прокси)"),
            // tr(settings.language, "Launch TUN tunnel (virtual interface)", "Запустить TUN туннель (виртуальный интерфейс)"),
            tr(settings.language, "Per-app proxy (route specific apps)", "Прокси для приложений (выбрать приложения)"),
            tr(settings.language, "Profiles", "Профили"),
            tr(settings.language, "Settings", "Настройки")
        };
        if (xrayRunning) {
            menuItems.push_back(tr(settings.language, "Show xray-core status", "Показать статус xray-core"));
#ifdef _WIN32
            menuItems.push_back(winProxyActive
                ? tr(settings.language, "Clear system proxy", "Отключить системный прокси")
                : tr(settings.language, "Set system proxy",   "Установить системный прокси"));
#endif
            if (tunnelModeActive && !tunModeActive) {
                std::string vpnStatus = systemVpnActive ?
                    tr(settings.language, "Disable system VPN", "Отключить системный VPN") :
                    tr(settings.language, "Enable system VPN", "Включить системный VPN");
                menuItems.push_back(vpnStatus);
            }
            if (!xrayRunning2) {
                menuItems.push_back(tr(settings.language, "Launch second proxy", "Запустить второй прокси"));
            } else {
                menuItems.push_back(tr(settings.language, "Show second proxy status", "Показать статус второго прокси"));
                menuItems.push_back(tr(settings.language, "Stop second proxy", "Остановить второй прокси"));
            }
            menuItems.push_back(tr(settings.language, "Stop xray-core", "Остановить xray-core"));
        }
        menuItems.push_back(tr(settings.language, "Exit", "Выход"));
        selected = (std::min)(selected, static_cast<int>(menuItems.size()) - 1);

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
#ifdef _WIN32
            if (winProxyActive)  clearWindowsSystemProxy(settings.language);
#endif
            if (activePid2 > 0)  stopXrayCore(activePid2);
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
                if (winProxyActive)  clearWindowsSystemProxy(settings.language);
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
        if (key == 20) { // Ctrl+T — main xray log
            if (xrayRunning && !activeLogFile.empty() && logsEnabled) {
                showXrayLog(activeLogFile, settings.language);
            }
            continue;
        }
        if (key == 'l' || key == 'L') { // L — traffic routing log (access log)
            if (xrayRunning && !activeAccessLogFile.empty()) {
                showXrayLog(activeAccessLogFile, settings.language);
            } else if (xrayRunning && !activeLogFile.empty()) {
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
            // std::string tunLaunchStr = tr(settings.language, "Launch TUN tunnel (virtual interface)", "...");
            std::string perAppStr    = tr(settings.language, "Per-app proxy (route specific apps)", "Прокси для приложений (выбрать приложения)");
            std::string profilesStr  = tr(settings.language, "Profiles", "Профили");
            std::string settingsStr  = tr(settings.language, "Settings", "Настройки");
            std::string statusStr    = tr(settings.language, "Show xray-core status", "Показать статус xray-core");
#ifdef _WIN32
            std::string winProxySetStr   = tr(settings.language, "Set system proxy",   "Установить системный прокси");
            std::string winProxyClearStr = tr(settings.language, "Clear system proxy", "Отключить системный прокси");
#endif
            std::string vpnEnableStr = tr(settings.language, "Enable system VPN", "Включить системный VPN");
            std::string vpnDisableStr= tr(settings.language, "Disable system VPN", "Отключить системный VPN");
            std::string stopStr      = tr(settings.language, "Stop xray-core", "Остановить xray-core");
            std::string exitStr      = tr(settings.language, "Exit", "Выход");
            std::string launch2Str   = tr(settings.language, "Launch second proxy", "Запустить второй прокси");
            std::string status2Str   = tr(settings.language, "Show second proxy status", "Показать статус второго прокси");
            std::string stop2Str     = tr(settings.language, "Stop second proxy", "Остановить второй прокси");

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
                            xrayRunning        = true;
                            tunnelModeActive   = false;
                            tunModeActive      = false;
                            systemVpnActive    = false;
                            activeAccessLogFile = "xray-access-" + std::to_string(settings.proxyPort) + ".log";
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
#ifdef _WIN32
                    Sleep(800);
#else
                    usleep(800000);
#endif
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
#ifdef _WIN32
            } else if (selectedItem == winProxySetStr) {
                clearScreen();
                if (setWindowsSystemProxy(settings.httpProxyPort, settings.proxyPort, settings.language)) {
                    winProxyActive = true;
                }
                pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
            } else if (selectedItem == winProxyClearStr) {
                clearScreen();
                clearWindowsSystemProxy(settings.language);
                winProxyActive = false;
                pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
#endif
            } else if (selectedItem == vpnEnableStr) {
                setupSystemVPN(settings, activePid);
                systemVpnActive = true;
            } else if (selectedItem == vpnDisableStr) {
                cleanupSystemVPN(settings);
                systemVpnActive = false;
            } else if (selectedItem == launch2Str) {
                // ── Launch second proxy instance ──────────────────────────────
                if (profiles.empty()) {
                    clearScreen();
                    std::cout << tr(settings.language, "No profiles available. Add profiles first.", "Нет доступных профилей. Сначала добавьте профили.") << "\n";
                    pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
                } else {
                    int idx = pickProfile();
                    if (idx >= 0) {
                        clearScreen();
                        std::cout << tr(settings.language, "Proxy protocol for second proxy:", "Протокол второго прокси:") << "\n";
                        std::cout << "1. SOCKS5\n";
                        std::cout << "2. HTTP\n";
                        std::cout << tr(settings.language, "Press 1 or 2 (default SOCKS5): ", "Нажмите 1 или 2 (по умолч. SOCKS5): ");
                        int pk = readKey();
                        std::string proxyProtocol2 = (pk == '2') ? "http" : "socks";
                        if (launchXrayCore(settings, profiles[idx], false, proxyProtocol2,
                                           activeLogFile2, listenAddress2, activePid2, 2)) {
                            xrayRunning2 = true;
                            showXrayLog(activeLogFile2, settings.language);
                        }
                    }
                }
            } else if (selectedItem == status2Str) {
                // ── Second proxy status ───────────────────────────────────────
                clearScreen();
                std::cout << "=== " << tr(settings.language, "Second proxy status", "Статус второго прокси") << " ===\n\n";
                std::cout << tr(settings.language, "PID:", "PID:") << " " << activePid2 << "\n";
                std::cout << tr(settings.language, "Listening on:", "Слушает:") << " " << listenAddress2 << "\n";
                std::cout << tr(settings.language, "Log file:", "Файл лога:") << " " << activeLogFile2 << "\n";
                std::cout << tr(settings.language, "Port:", "Порт:") << " " << settings.proxy2Port << "\n";
                pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
            } else if (selectedItem == stop2Str) {
                // ── Stop second proxy ─────────────────────────────────────────
                clearScreen();
                if (stopXrayCore(activePid2)) {
                    std::cout << tr(settings.language, "Second proxy stopped.", "Второй прокси остановлен.") << "\n";
                    activePid2 = 0;
                    xrayRunning2 = false;
                    listenAddress2.clear();
                } else {
                    std::cout << tr(settings.language, "Failed to stop second proxy.", "Не удалось остановить второй прокси.") << "\n";
                }
                pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
            } else if (selectedItem == stopStr) {
                clearScreen();
                // Stop second proxy if running
                if (xrayRunning2 && activePid2 > 0) {
                    stopXrayCore(activePid2);
                    activePid2 = 0;
                    xrayRunning2 = false;
                    listenAddress2.clear();
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
#ifdef _WIN32
                if (winProxyActive) {
                    clearWindowsSystemProxy(settings.language);
                    winProxyActive = false;
                }
#endif
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
                std::cout << tr(settings.language, "Exit...", "Выход...") << "\n";
                return 0;
            }
        }
    }

    return 0;
}
