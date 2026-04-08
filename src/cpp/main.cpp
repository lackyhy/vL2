#include <iostream>
#include <vector>
#include <filesystem>
#include <signal.h>
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
    bool tunnelModeActive = false;
    bool systemVpnActive = false;
    ProcessId activePid = 0;
    std::string listenAddress;
    std::string activeLogFile;

    signal(SIGINT, SIG_IGN);
    loadSettings(settings);
    loadProfiles(profiles);

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
            std::cout << tr(settings.language, "Active xray-core PID:", "Активный PID xray-core:") << " " << activePid << "\n";
            std::cout << tr(settings.language, "Listening on:", "Слушает:") << " " << listenAddress << "\n";
        }
        std::cout << "\n";
        std::cout << tr(settings.language, "Use arrow keys or type a number to choose.", "Используйте стрелки или введите цифру для выбора.") << "\n";
        std::cout << tr(settings.language, "Press Enter to execute. Press Q to quit.", "Нажмите Enter для выполнения. Q — выход.") << "\n\n";

        std::vector<std::string> menuItems = {
            tr(settings.language, "Launch xray-core", "Запустить xray-core"),
            tr(settings.language, "Profiles", "Профили"),
            tr(settings.language, "Settings", "Настройки")
        };
        if (xrayRunning) {
            menuItems.push_back(tr(settings.language, "Show xray-core status", "Показать статус xray-core"));
            if (tunnelModeActive) {
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
            if (systemVpnActive) {
                cleanupSystemVPN(settings);
            }
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
                if (systemVpnActive) cleanupSystemVPN(settings);
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
            std::string launchStr = tr(settings.language, "Launch xray-core", "Запустить xray-core");
            std::string profilesStr = tr(settings.language, "Profiles", "Профили");
            std::string settingsStr = tr(settings.language, "Settings", "Настройки");
            std::string statusStr = tr(settings.language, "Show xray-core status", "Показать статус xray-core");
            std::string vpnEnableStr = tr(settings.language, "Enable system VPN", "Включить системный VPN");
            std::string vpnDisableStr = tr(settings.language, "Disable system VPN", "Отключить системный VPN");
            std::string stopStr = tr(settings.language, "Stop xray-core", "Остановить xray-core");
            std::string exitStr = tr(settings.language, "Exit", "Выход");
            
            if (selectedItem == launchStr) {
                // Launch xray-core
                if (profiles.empty()) {
                    clearScreen();
                    std::cout << tr(settings.language, "No profiles available. Add profiles first.", "Нет доступных профилей. Сначала добавьте профили.") << "\n";
                    pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
                } else {
                    // Show profiles and select one
                    clearScreen();
                    std::cout << tr(settings.language, "Select profile to launch:", "Выберите профиль для запуска:") << "\n\n";
                    for (size_t i = 0; i < profiles.size(); ++i) {
                        std::cout << i + 1 << ". " << profiles[i].name << " (" << profiles[i].type << ")\n";
                    }
                    std::cout << "\n" << tr(settings.language, "Enter number (1-", "Введите номер (1-") << profiles.size() << "): ";
                    std::string choiceLine;
                    std::getline(std::cin >> std::ws, choiceLine);
                    int choice = 0;
                    try {
                        choice = std::stoi(choiceLine);
                    } catch (...) {
                        choice = 0;
                    }
                    if (choice >= 1 && choice <= static_cast<int>(profiles.size())) {
                        clearScreen();
                        std::cout << tr(settings.language, "Choose launch mode:", "Выберите режим запуска:") << "\n";
                        std::cout << "1. " << tr(settings.language, "Proxy mode", "Режим прокси") << "\n";
                        std::cout << "2. " << tr(settings.language, "Tunnel mode", "Режим туннеля") << "\n";
                        std::cout << tr(settings.language, "Press 1 or 2:", "Нажмите 1 или 2:") << " ";
                        int modeChoice = 0;
                        std::string modeLine;
                        std::getline(std::cin >> std::ws, modeLine);
                        try {
                            modeChoice = std::stoi(modeLine);
                        } catch (...) {
                            modeChoice = 0;
                        }
                        bool tunnelMode = (modeChoice == 2);
                        std::string proxyProtocol = "socks";
                        
                        if (!tunnelMode) {
                            // Choose proxy protocol
                            clearScreen();
                            std::cout << tr(settings.language, "Choose proxy protocol:", "Выберите протокол прокси:") << "\n";
                            std::cout << "1. SOCKS5\n";
                            std::cout << "2. HTTP\n";
                            std::cout << tr(settings.language, "Press 1 or 2:", "Нажмите 1 или 2:") << " ";
                            int protocolChoice = 0;
                            std::string protocolLine;
                            std::getline(std::cin >> std::ws, protocolLine);
                            try {
                                protocolChoice = std::stoi(protocolLine);
                            } catch (...) {
                                protocolChoice = 1;
                            }
                            proxyProtocol = (protocolChoice == 2) ? "http" : "socks";
                        }
                        
                        if (launchXrayCore(settings, profiles[choice - 1], tunnelMode, proxyProtocol, activeLogFile, listenAddress, activePid)) {
                            xrayRunning = true;
                            tunnelModeActive = tunnelMode;
                            systemVpnActive = false;
                            showXrayLog(activeLogFile, settings.language);
                        }
                    } else {
                        std::cout << tr(settings.language, "Invalid choice.", "Неверный выбор.") << "\n";
                        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
                    }
                }
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
                std::cout << tr(settings.language, "xray-core status:", "Статус xray-core:") << "\n";
                std::cout << tr(settings.language, "Running PID:", "Запущен PID:") << " " << activePid << "\n";
                std::cout << tr(settings.language, "Listening on:", "Слушает:") << " " << listenAddress << "\n";
                if (tunnelModeActive) {
                    std::cout << "\n" << tr(settings.language, "Tunnel mode active", "Режим туннеля активен") << "\n";
                    if (systemVpnActive) {
                        std::cout << tr(settings.language, "System VPN enabled", "Системный VPN включен") << "\n";
                        std::cout << tr(settings.language, "Active pfctl redirect rules:", "Активные правила перенаправления pfctl:") << "\n";
                        system("sudo pfctl -s rules 2>/dev/null | grep 'rdr' || echo 'No redirect rules found'");
                    } else {
                        std::cout << tr(settings.language, "System VPN disabled", "Системный VPN отключен") << "\n";
                    }
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
                if (systemVpnActive) {
                    cleanupSystemVPN(settings);
                    systemVpnActive = false;
                }
                if (stopXrayCore(activePid)) {
                    std::cout << tr(settings.language, "xray-core stopped successfully.", "xray-core успешно остановлен.") << "\n";
                    activePid = 0;
                    xrayRunning = false;
                    tunnelModeActive = false;
                } else {
                    std::cout << tr(settings.language, "Failed to stop xray-core.", "Не удалось остановить xray-core.") << "\n";
                }
                pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
            } else if (selectedItem == exitStr) {
                showCursor();
                clearScreen();
                if (systemVpnActive) {
                    cleanupSystemVPN(settings);
                }
                std::cout << tr(settings.language, "Exit...", "Выход...") << "\n";
                return 0;
            }
        }
    }

    return 0;
}
