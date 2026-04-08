#include "XrayLauncher.h"
#include "ConsoleUtils.h"
#include "xray_embedded.h"
#include <filesystem>
#include <iostream>
#include <sstream>
#include <regex>
#include <fstream>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#if defined(__unix__) || defined(__APPLE__)
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

std::string generateConfig(const Profile& profile) {
    return generateConfig(profile, false);
}

std::string generateConfig(const Profile& profile, bool tunnelMode) {
    return generateConfig(profile, tunnelMode, "socks");
}

std::string generateConfig(const Profile& profile, bool tunnelMode, const std::string& proxyProtocol) {
    return generateConfig(profile, tunnelMode, proxyProtocol, 1080);
}

std::string generateConfig(const Profile& profile, bool tunnelMode, const std::string& proxyProtocol, int port) {
    std::ostringstream oss;
    std::string inboundProto = tunnelMode ? "dokodemo-door" : proxyProtocol;
    std::string listenAddr = "127.0.0.1";  // Always listen on localhost for transparent redirect

    oss << R"(
{
  "inbounds": [
    {
      "port": )" << port << R"(,
      "listen": ")" << listenAddr << R"(",
      "protocol": ")" << inboundProto << R"(",
      "settings": {
)";
    if (tunnelMode) {
        oss << R"(
        "address": "0.0.0.0",
        "port": 0,
        "network": ["tcp", "udp"],
        "followRedirect": true,
        "timeout": 300
)";
    } else if (proxyProtocol == "http") {
        oss << R"(
        "timeout": 360,
        "allowTransparent": false
)";
    } else {
        // SOCKS
        oss << R"(
        "auth": "noauth"
)";
    }
    oss << R"(
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
)";

    if (profile.type == "VLESS") {
        // Parse address: host:port
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        if (std::regex_match(profile.address, match, addrRegex)) {
            std::string host = match[1].str();
            std::string port = match[2].str();
            std::string uuid = profile.uuid.empty() ? "fc1e5950-d7eb-4032-a22f-67031e41c8b6" : profile.uuid;
            std::string encryption = profile.encryption.empty() ? "none" : profile.encryption;
            std::string flow = profile.flow;
            
            oss << R"(
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": ")" << host << R"(",
            "port": )" << port << R"(,
            "users": [
              {
                "id": ")" << uuid << R"(",
                "encryption": ")" << encryption << R"(")"
                << (flow.empty() ? "" : ",\n                \"flow\": \"" + flow + "\"")
                << R"(
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "www.apple.com",
          "fingerprint": "chrome",
          "publicKey": "Y0jh08ES3fy99G7kYHOa7K7BxQuclneLl1GMcpe3MyA",
          "shortId": "95",
          "spiderX": "/"

        }
      }
)";
        }
    } else if (profile.type == "VMess") {
        // Similar for VMess
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        std::string host = "example.com";
        std::string port = "443";
        if (std::regex_match(profile.address, match, addrRegex)) {
            host = match[1].str();
            port = match[2].str();
        }
        std::string uuid = profile.uuid.empty() ? "uuid" : profile.uuid;
        
        oss << R"(
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": ")" << host << R"(",
            "port": )" << port << R"(,
            "users": [
              {
                "id": ")" << uuid << R"(",
                "alterId": 0
              }
            ]
          }
        ]
      }
)";
    } else {
        // Default
        oss << R"(
      "protocol": "freedom"
)";
    }

    oss << R"(
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "outboundTag": "proxy",
        "ip": [
          "0.0.0.0/0",
          "::/0"
        ]
      }
    ]
  }
}
)";
    return oss.str();
}

static bool isExecutableFile(const fs::path& path) {
    return fs::exists(path) && fs::is_regular_file(path);
}

std::string extractEmbeddedXray() {
#ifndef VL2_EMBED_XRAY
    return {};
#else
    if (g_xray_size == 0) return {};

    // ── Choose extraction directory ────────────────────────────────────────
#ifdef _WIN32
    char tmpBuf[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tmpBuf);
    std::string extractDir = std::string(tmpBuf) + "vl2_xray";
    std::string extractPath = extractDir + "\\xray.exe";
    CreateDirectoryA(extractDir.c_str(), nullptr);
#else
    const char* tmpBase = std::getenv("TMPDIR");
    std::string extractDir = std::string(tmpBase ? tmpBase : "/tmp") + "/vl2_xray";
    std::string extractPath = extractDir + "/xray";
    mkdir(extractDir.c_str(), 0755);
#endif

    // ── Skip extraction if already up-to-date ─────────────────────────────
    std::error_code ec;
    auto existingSize = fs::file_size(extractPath, ec);
    if (!ec && existingSize == static_cast<uintmax_t>(g_xray_size)) {
        return extractPath;  // already extracted, same size
    }

    // ── Write embedded bytes to disk ──────────────────────────────────────
    {
        std::ofstream out(extractPath, std::ios::binary | std::ios::trunc);
        if (!out) return {};
        out.write(reinterpret_cast<const char*>(g_xray_data),
                  static_cast<std::streamsize>(g_xray_size));
    }

#if defined(__unix__) || defined(__APPLE__)
    chmod(extractPath.c_str(), 0755);
#endif

    return extractPath;
#endif // VL2_EMBED_XRAY
}

static bool isXrayProcessRunning(ProcessId pid) {
#ifdef _WIN32
    return pid != 0;
#else
    if (pid <= 0) return false;
    return kill(static_cast<pid_t>(pid), 0) == 0 || errno != ESRCH;
#endif
}

static std::vector<fs::path> buildSearchPaths(const Settings& settings) {
    std::vector<fs::path> searchPaths;
    if (!settings.xrayCoreDir.empty()) {
        searchPaths.emplace_back(settings.xrayCoreDir);
    }
    searchPaths.emplace_back(fs::current_path());
    searchPaths.emplace_back(fs::current_path() / "xray");
    searchPaths.emplace_back(fs::current_path() / "xray-core");
    searchPaths.emplace_back(fs::current_path() / "bin");
    return searchPaths;
}

std::string findXrayCoreBinary(const Settings& settings) {
    // ── 1. Try embedded binary first ──────────────────────────────────────
    std::string embedded = extractEmbeddedXray();
    if (!embedded.empty() && fs::exists(embedded)) {
        return embedded;
    }

    // ── 2. Fall back to filesystem search ─────────────────────────────────
    std::vector<std::string> candidates = {"xray-core", "xray", "xray-core.exe", "xray.exe"};
    for (const auto& path : buildSearchPaths(settings)) {
        if (fs::is_directory(path)) {
            for (const auto& name : candidates) {
                fs::path candidate = path / name;
                if (isExecutableFile(candidate)) {
                    return candidate.string();
                }
            }
        } else {
            if (isExecutableFile(path)) {
                return path.string();
            }
        }
    }

    const char* pathEnv = std::getenv("PATH");
    if (pathEnv) {
        std::string pathValue(pathEnv);
        std::string separator =
#ifdef _WIN32
            ";";
#else
            ":";
#endif
        size_t pos = 0;
        while (pos < pathValue.size()) {
            size_t next = pathValue.find(separator, pos);
            if (next == std::string::npos) {
                next = pathValue.size();
            }
            fs::path candidatePath = pathValue.substr(pos, next - pos);
            for (const auto& name : candidates) {
                fs::path candidate = candidatePath / name;
                if (isExecutableFile(candidate)) {
                    return candidate.string();
                }
            }
            pos = next + separator.size();
        }
    }
    return {};
}

bool launchXrayCore(const Settings& settings, const Profile& profile, bool tunnelMode, const std::string& proxyProtocol, std::string& outLogFile, std::string& outListenAddress, ProcessId& outPid) {
    clearScreen();
    std::cout << "=== " << tr(settings.language, "Launch xray-core", "Запуск xray-core") << " ===\n\n";

    std::string binaryPath = findXrayCoreBinary(settings);
    if (binaryPath.empty()) {
        std::cout << tr(settings.language,
            "xray-core binary not found. Put xray binary into the xray/ folder and try again.",
            "Бинарник xray-core не найден. Поместите бинарник xray в папку xray/ и попробуйте снова.") << "\n";
        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }

    std::cout << tr(settings.language, "Found: ", "Найден: ") << binaryPath << "\n";

    // Quick availability check (silent)
    std::vector<std::string> versionArgs = {"-version", "--version", "version"};
    bool available = false;
    for (const auto& arg : versionArgs) {
        std::string command;
#ifdef _WIN32
        command = "\"" + binaryPath + "\" " + arg + " >nul 2>&1";
#else
        command = "\"" + binaryPath + "\" " + arg + " >/dev/null 2>&1";
#endif
        if (std::system(command.c_str()) == 0) {
            available = true;
            break;
        }
    }
    if (!available) {
        std::cout << tr(settings.language,
            "Warning: binary version check failed. Make sure it is executable.",
            "Предупреждение: проверка версии бинарника не прошла. Убедитесь, что он исполняемый.") << "\n";
#if defined(__unix__) || defined(__APPLE__)
        std::cout << "  chmod +x \"" << binaryPath << "\"\n";
#endif
    }

    int port = settings.proxyPort > 0 ? settings.proxyPort : 1080;
    std::string actualProxyProtocol = tunnelMode ? "dokodemo-door" : proxyProtocol;
    std::string config = generateConfig(profile, tunnelMode, actualProxyProtocol, port);

    std::ofstream configFile("config.json");
    if (!configFile) {
        std::cout << tr(settings.language, "Failed to create config.json", "Не удалось создать config.json") << "\n";
        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    configFile << config;
    configFile.close();

    outLogFile = "xray-core.log";
    std::cout << tr(settings.language, "Starting xray-core...", "Запуск xray-core...") << "\n";

#ifdef _WIN32
    std::string launchCommand = "start /B \"\" \"" + binaryPath + "\" -config config.json >" + outLogFile + " 2>&1";
    int launchResult = std::system(launchCommand.c_str());
    outPid = 0;
    // On Windows, try to find the PID via tasklist
    if (launchResult == 0) {
        FILE* pipe = _popen("tasklist /FI \"IMAGENAME eq xray.exe\" /FO CSV /NH 2>nul", "r");
        if (pipe) {
            char buf[256] = {0};
            if (fgets(buf, sizeof(buf), pipe)) {
                // CSV format: "xray.exe","PID",...
                char* pidStart = strchr(buf, ',');
                if (pidStart) {
                    pidStart++; // skip comma
                    if (*pidStart == '"') pidStart++;
                    outPid = strtol(pidStart, nullptr, 10);
                }
            }
            _pclose(pipe);
        }
    }
#else
    std::string launchCommand = "nohup \"" + binaryPath + "\" -config config.json >" + outLogFile + " 2>&1 & echo $!";
    FILE* pipe = popen(launchCommand.c_str(), "r");
    if (!pipe) {
        std::cout << tr(settings.language, "Failed to start xray-core process.", "Не удалось запустить процесс xray-core.") << "\n";
        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    char pidBuffer[32] = {0};
    if (!fgets(pidBuffer, sizeof(pidBuffer), pipe)) {
        pclose(pipe);
        std::cout << tr(settings.language, "Failed to read xray-core process id.", "Не удалось прочитать PID процесса xray-core.") << "\n";
        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    pclose(pipe);
    outPid = strtol(pidBuffer, nullptr, 10);
    int launchResult = (outPid > 0) ? 0 : -1;
#endif

    if (launchResult != 0) {
        std::cout << tr(settings.language,
            "Failed to start xray-core. See log for details: ",
            "Не удалось запустить xray-core. Смотрите лог: ") << outLogFile << "\n";
        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }

    std::string listenAddress = "127.0.0.1:" + std::to_string(port);
    std::cout << tr(settings.language, "xray-core started. Log: ", "xray-core запущен. Лог: ") << outLogFile << "\n";
    std::cout << tr(settings.language, "Listening on: ", "Слушает: ") << listenAddress << "\n";
    if (tunnelMode) {
        std::cout << tr(settings.language,
            "Tunnel mode active. Use 'Enable system VPN' to redirect all traffic.",
            "Режим туннеля активен. Используйте 'Включить системный VPN' для перенаправления трафика.") << "\n";
    } else {
        std::cout << tr(settings.language, "Proxy mode: ", "Режим прокси: ") << actualProxyProtocol
                  << " -> " << listenAddress << "\n";
    }
    outListenAddress = listenAddress;
    pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
    return true;
}

bool stopXrayCore(ProcessId pid) {
#ifdef _WIN32
    if (pid <= 0) return false;
    std::string command = "taskkill /PID " + std::to_string(pid) + " /T /F >nul 2>&1";
    return std::system(command.c_str()) == 0;
#else
    if (pid <= 0) return false;
    if (kill(static_cast<pid_t>(pid), SIGTERM) == 0) return true;
    if (errno == ESRCH) return false;
    return kill(static_cast<pid_t>(pid), SIGKILL) == 0;
#endif
}

bool isXrayRunning(ProcessId pid) {
    return isXrayProcessRunning(pid);
}

XrayProcessInfo findRunningXrayProcess() {
    XrayProcessInfo info;
    info.pid = 0;
#if defined(__unix__) || defined(__APPLE__)
    // Look for xray process (exclude grep itself with [x]ray pattern)
    FILE* pipe = popen("ps aux 2>/dev/null | grep '[x]ray' | head -1", "r");
    if (!pipe) return info;
    
    char line[1024] = {0};
    if (fgets(line, sizeof(line), pipe)) {
        // Parse ps output format: user pid cpu mem vsz rss tty stat start time command...
        long pid = 0;
        int fields = sscanf(line, "%*s %ld", &pid);
        if (fields == 1 && pid > 0) {
            info.pid = static_cast<ProcessId>(pid);
            
            // Extract command path - it's usually at the end
            char* cmd = strrchr(line, ' ');
            while (cmd && *cmd == ' ') cmd--;
            if (cmd) {
                char* fullLine = line;
                // Skip past the first 11-12 fields to get to the command
                for (int i = 0; i < 11 && fullLine; ++i) {
                    fullLine = strchr(fullLine + 1, ' ');
                }
                if (fullLine) {
                    while (*fullLine == ' ') fullLine++;
                    fullLine[strcspn(fullLine, "\n")] = 0;
                    info.binaryPath = fullLine;
                    if (info.binaryPath.empty()) {
                        info.binaryPath = "xray (path unknown)";
                    }
                } else {
                    info.binaryPath = "xray (path unknown)";
                }
            }
        }
    }
    pclose(pipe);
    
    // Try to determine listening address by checking ports
    if (info.pid > 0) {
        char lsofCmd[256];
        snprintf(lsofCmd, sizeof(lsofCmd), "lsof -p %ld 2>/dev/null | grep -E 'LISTEN|1080' | head -1", info.pid);
        pipe = popen(lsofCmd, "r");
        if (pipe) {
            char lsofLine[512] = {0};
            if (fgets(lsofLine, sizeof(lsofLine), pipe)) {
                // Look for port 1080 in lsof output
                if (strstr(lsofLine, "1080")) {
                    info.listenAddress = "127.0.0.1:1080 or 0.0.0.0:1080";
                }
            }
            pclose(pipe);
        }
    }
#endif
    return info;
}

void showXrayLog(const std::string& logFile, Language lang) {
    clearScreen();
    std::cout << "=== " << tr(lang, "xray-core logs", "Логи xray-core") << " ===\n\n";

    std::ifstream file(logFile);
    if (!file) {
        std::cout << tr(lang, "Log file not found.", "Файл лога не найден.") << "\n";
    } else {
        std::string line;
        std::vector<std::string> lines;
        while (std::getline(file, line)) {
            lines.push_back(line);
            if (lines.size() > 40) {
                lines.erase(lines.begin());
            }
        }
        for (const auto& l : lines) {
            std::cout << l << "\n";
        }
        if (lines.empty()) {
            std::cout << tr(lang, "No log output yet.", "Пока нет вывода лога.") << "\n";
        }
    }

    std::cout << "\n" << tr(lang, "Press any key to return to main menu.", "Нажмите любую клавишу, чтобы вернуться в главное меню.") << "\n";
    pauseScreen("");
}

bool setupSystemVPN(const Settings& settings, ProcessId xrayPid) {
    if (xrayPid <= 0) return false;

    int port = settings.proxyPort > 0 ? settings.proxyPort : 1080;
    std::string portStr = std::to_string(port);
    std::string listenAddr = "127.0.0.1:" + portStr;

    clearScreen();
    std::cout << tr(settings.language, "Setting up system-wide VPN...", "Настройка системного VPN...") << "\n\n";

#ifdef __APPLE__
    std::cout << "macOS: " << tr(settings.language,
        "Configuring transparent proxy with pfctl...",
        "Настройка прозрачного прокси через pfctl...") << "\n";
    std::cout << tr(settings.language, "This requires sudo password.", "Требуется пароль sudo.") << "\n\n";

    std::string anchorFile = "/tmp/vl2_pfctl_rules.conf";
    std::ofstream ruleFile(anchorFile);
    if (!ruleFile) {
        std::cout << tr(settings.language, "Error: Cannot create pfctl rules file", "Ошибка: не удалось создать файл правил pfctl") << "\n";
        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }

    ruleFile << "# vL2 pfctl rules — proxy port " << portStr << "\n";
    ruleFile << "nat pass on ! lo0 inet proto tcp from any to any port 80  -> 127.0.0.1 port " << portStr << "\n";
    ruleFile << "nat pass on ! lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port " << portStr << "\n";
    ruleFile << "nat pass on ! lo0 inet proto udp from any to any port 53  -> 127.0.0.1 port " << portStr << "\n";
    ruleFile << "pass out inet proto tcp from 127.0.0.1 to any\n";
    ruleFile << "pass out inet proto udp from 127.0.0.1 to any\n";
    ruleFile << "pass in  inet proto tcp to 127.0.0.1 port " << portStr << "\n";
    ruleFile.close();

    int result = system("sudo pfctl -e 2>/dev/null");
    if (result != 0) {
        std::cout << tr(settings.language, "  (pfctl may already be enabled)", "  (pfctl уже включен)") << "\n";
    }

    std::string applyCmd = "sudo pfctl -f " + anchorFile;
    result = system(applyCmd.c_str());
    std::cout << (result == 0
        ? tr(settings.language, "pfctl rules applied.", "Правила pfctl применены.")
        : tr(settings.language, "Warning: pfctl apply may have failed.", "Предупреждение: применение pfctl могло завершиться с ошибкой."))
        << "\n";

    system(("rm -f " + anchorFile).c_str());

    std::cout << tr(settings.language, "System VPN enabled.", "Системный VPN включен.") << "\n";

#elif defined(__linux__)
    std::cout << "Linux: " << tr(settings.language,
        "Configuring transparent proxy with iptables...",
        "Настройка прозрачного прокси через iptables...") << "\n";
    std::cout << tr(settings.language, "This requires sudo password.", "Требуется пароль sudo.") << "\n\n";

    system("sudo iptables-save > /tmp/vl2_iptables_backup 2>/dev/null");
    system("sudo sysctl -q net.ipv4.ip_forward=1 2>/dev/null");
    system("sudo iptables -t nat -F 2>/dev/null");
    system("sudo iptables -t nat -X 2>/dev/null");

    std::string toPort = " --to-port " + portStr + " 2>/dev/null";
    system(("sudo iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT" + toPort).c_str());
    system(("sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT" + toPort).c_str());
    system(("sudo iptables -t nat -A OUTPUT -p udp --dport 53  -j REDIRECT" + toPort).c_str());
    system("echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf > /dev/null 2>&1");

    std::cout << tr(settings.language, "System VPN enabled.", "Системный VPN включен.") << "\n";

#elif defined(_WIN32)
    std::cout << "Windows: " << tr(settings.language,
        "Configuring system proxy via registry and WinHTTP...",
        "Настройка системного прокси через реестр и WinHTTP...") << "\n\n";

    // Format: socks=host:port;http=host:port;https=host:port
    std::string proxyValue = "socks=" + listenAddr + ";http=" + listenAddr + ";https=" + listenAddr;

    // Set IE/WinInet proxy (affects browsers, .NET, most apps)
    std::string regPath = "\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\"";
    std::string enableCmd = "reg add " + regPath + " /v ProxyEnable /t REG_DWORD /d 1 /f >nul 2>&1";
    std::string serverCmd = "reg add " + regPath + " /v ProxyServer /t REG_SZ /d \"" + proxyValue + "\" /f >nul 2>&1";
    std::string overrideCmd = "reg add " + regPath + " /v ProxyOverride /t REG_SZ /d \"localhost;127.*;<local>\" /f >nul 2>&1";

    system(enableCmd.c_str());
    system(serverCmd.c_str());
    system(overrideCmd.c_str());

    // Set WinHTTP proxy (affects system-level HTTP clients, some apps)
    std::string winHttpCmd = "netsh winhttp set proxy proxy-server=\"" + listenAddr + "\" bypass-list=\"localhost;127.*;::1\" >nul 2>&1";
    system(winHttpCmd.c_str());

    std::cout << tr(settings.language, "System proxy set: ", "Системный прокси установлен: ") << listenAddr << "\n";
    std::cout << tr(settings.language,
        "Proxy type: SOCKS5/HTTP/HTTPS -> xray-core.\n"
        "Note: Apps already running may need a restart to pick up the proxy.",
        "Тип прокси: SOCKS5/HTTP/HTTPS -> xray-core.\n"
        "Примечание: уже запущенные приложения могут потребовать перезапуска.") << "\n";
#endif

    std::cout << tr(settings.language,
        "All system traffic now routes through xray-core at ",
        "Весь системный трафик теперь маршрутизируется через xray-core на ")
        << listenAddr << "\n";
    std::cout << tr(settings.language,
        "To disable: use 'Disable system VPN' from the menu.",
        "Для отключения: используйте 'Отключить системный VPN' из меню.") << "\n";
    pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
    return true;
}

bool cleanupSystemVPN(const Settings& settings) {
    clearScreen();
    std::cout << tr(settings.language, "Cleaning up system VPN rules...", "Очистка правил системного VPN...") << "\n";

#ifdef __APPLE__
    system("sudo pfctl -F rules 2>/dev/null");
    system("sudo pfctl -F nat 2>/dev/null");
    std::cout << tr(settings.language, "pfctl rules cleared.", "Правила pfctl очищены.") << "\n";
#elif defined(__linux__)
    system("sudo iptables -t nat -F 2>/dev/null");
    system("sudo iptables -t nat -X 2>/dev/null");
    if (std::ifstream("/tmp/vl2_iptables_backup")) {
        system("sudo iptables-restore < /tmp/vl2_iptables_backup 2>/dev/null");
        system("rm -f /tmp/vl2_iptables_backup");
    }
    system("sudo systemctl restart systemd-resolved 2>/dev/null");
    std::cout << tr(settings.language, "iptables rules cleared.", "Правила iptables очищены.") << "\n";
#elif defined(_WIN32)
    // Disable IE/WinInet proxy
    std::string regPath = "\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\"";
    system(("reg add " + regPath + " /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1").c_str());
    system(("reg delete " + regPath + " /v ProxyServer /f >nul 2>&1").c_str());
    system(("reg delete " + regPath + " /v ProxyOverride /f >nul 2>&1").c_str());
    // Reset WinHTTP proxy
    system("netsh winhttp reset proxy >nul 2>&1");
    std::cout << tr(settings.language, "System proxy disabled.", "Системный прокси отключен.") << "\n";
#endif

    std::cout << tr(settings.language, "System VPN cleaned up.", "Системный VPN очищен.") << "\n";
    pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
    return true;
}

bool downloadXrayCore(const Settings& settings) {
    std::string osName, arch, zipName, tempZip, extractDir;

#ifdef __APPLE__
    osName = "macos";
    // Detect Apple Silicon vs Intel
    FILE* archPipe = popen("uname -m 2>/dev/null", "r");
    char archBuf[16] = "64";
    if (archPipe) {
        if (fgets(archBuf, sizeof(archBuf), archPipe)) {
            archBuf[strcspn(archBuf, "\n")] = 0;
        }
        pclose(archPipe);
    }
    arch = (std::string(archBuf).find("arm") != std::string::npos) ? "arm64-v8a" : "64";
    zipName = "Xray-" + osName + "-" + arch + ".zip";
    tempZip = "/tmp/" + zipName;
    extractDir = "xray";

#elif defined(__linux__)
    osName = "linux";
    FILE* archPipe = popen("uname -m 2>/dev/null", "r");
    char archBuf[16] = "64";
    if (archPipe) {
        if (fgets(archBuf, sizeof(archBuf), archPipe)) {
            archBuf[strcspn(archBuf, "\n")] = 0;
        }
        pclose(archPipe);
    }
    std::string machineArch(archBuf);
    if (machineArch == "aarch64" || machineArch == "arm64") {
        arch = "arm64-v8a";
    } else if (machineArch.find("arm") != std::string::npos) {
        arch = "arm32-v7a";
    } else {
        arch = "64";
    }
    zipName = "Xray-" + osName + "-" + arch + ".zip";
    tempZip = "/tmp/" + zipName;
    extractDir = "xray";

#elif defined(_WIN32)
    osName = "windows";
    arch = "64";
    zipName = "Xray-" + osName + "-" + arch + ".zip";
    tempZip = std::string(std::getenv("TEMP") ? std::getenv("TEMP") : "C:\\Temp") + "\\" + zipName;
    extractDir = "xray";
#else
    std::cout << tr(settings.language, "Unsupported OS for auto-download.", "Автозагрузка не поддерживается для этой ОС.") << "\n";
    return false;
#endif

    std::string downloadUrl = "https://github.com/XTLS/Xray-core/releases/latest/download/" + zipName;

    std::cout << tr(settings.language, "Downloading: ", "Скачивание: ") << downloadUrl << "\n";

#ifdef _WIN32
    system(("if not exist " + extractDir + " mkdir " + extractDir).c_str());
    std::string dlCmd = "powershell -Command \"Invoke-WebRequest -Uri '" + downloadUrl + "' -OutFile '" + tempZip + "'\"";
    int result = system(dlCmd.c_str());
    if (result != 0) {
        std::cout << tr(settings.language, "Download failed.", "Ошибка скачивания.") << "\n";
        return false;
    }
    std::string unzipCmd = "powershell -Command \"Expand-Archive -Path '" + tempZip + "' -DestinationPath '" + extractDir + "' -Force\"";
    result = system(unzipCmd.c_str());
    system(("del /f \"" + tempZip + "\" 2>nul").c_str());
#else
    system(("mkdir -p " + extractDir).c_str());
    std::string curlCmd = "curl -L --progress-bar -o \"" + tempZip + "\" \"" + downloadUrl + "\"";
    int result = system(curlCmd.c_str());
    if (result != 0) {
        std::cout << tr(settings.language, "Download failed.", "Ошибка скачивания.") << "\n";
        return false;
    }
    std::cout << tr(settings.language, "Extracting...", "Распаковка...") << "\n";
    std::string unzipCmd = "unzip -o \"" + tempZip + "\" -d \"" + extractDir + "\"";
    result = system(unzipCmd.c_str());
    system(("rm -f \"" + tempZip + "\"").c_str());
#endif

    if (result != 0) {
        std::cout << tr(settings.language, "Extraction failed.", "Ошибка распаковки.") << "\n";
        return false;
    }

    std::string xrayPath = findXrayCoreBinary(settings);
    if (!xrayPath.empty() && std::filesystem::exists(xrayPath)) {
#if defined(__unix__) || defined(__APPLE__)
        system(("chmod +x \"" + xrayPath + "\" 2>/dev/null").c_str());
#endif
        std::cout << tr(settings.language, "Xray-core installed: ", "Xray-core установлен: ") << xrayPath << "\n";
        return true;
    }
    std::cout << tr(settings.language,
        "Xray-core binary not found after extraction. Check the xray/ folder manually.",
        "Бинарник xray-core не найден после распаковки. Проверьте папку xray/ вручную.") << "\n";
    return false;
}
