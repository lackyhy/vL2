#include "Menu.h"
#include "ConsoleUtils.h"
#include "Settings.h"
#include "XrayLauncher.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <climits>
#elif defined(__linux__)
#include <unistd.h>
#include <climits>
#endif

namespace fs = std::filesystem;

// Returns the directory where the vL2 executable lives.
// Settings and profiles are stored there so they follow the binary, not cwd.
static std::string getDataDir() {
#ifdef _WIN32
    char buf[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, buf, MAX_PATH)) {
        return fs::path(buf).parent_path().string();
    }
#elif defined(__APPLE__)
    char buf[PATH_MAX] = {0};
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        char resolved[PATH_MAX] = {0};
        if (realpath(buf, resolved)) {
            return fs::path(resolved).parent_path().string();
        }
    }
#elif defined(__linux__)
    char buf[PATH_MAX] = {0};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        return fs::path(buf).parent_path().string();
    }
#endif
    return "."; // fallback
}

static std::string encryptDecrypt(const std::string& data, const std::string& key) {
    std::string result = data;
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

static std::string serializeProfile(const Profile& profile) {
    return profile.name + "\t" + profile.type + "\t" + profile.address + "\t" +
           profile.uuid + "\t" + profile.encryption + "\t" + profile.flow + "\t" +
           profile.method + "\t" + profile.password + "\t" + profile.proxyProtocol + "\t" +
           profile.sni + "\t" + profile.fingerprint + "\t" + profile.publicKey + "\t" +
           profile.shortId + "\t" + profile.spiderX + "\t" + profile.security + "\n";
}

static Profile deserializeProfile(const std::string& line) {
    Profile p;
    std::istringstream iss(line);
    std::getline(iss, p.name, '\t');
    std::getline(iss, p.type, '\t');
    std::getline(iss, p.address, '\t');
    std::getline(iss, p.uuid, '\t');
    std::getline(iss, p.encryption, '\t');
    std::getline(iss, p.flow, '\t');
    std::getline(iss, p.method, '\t');
    std::getline(iss, p.password, '\t');
    std::getline(iss, p.proxyProtocol, '\t');
    std::getline(iss, p.sni, '\t');
    std::getline(iss, p.fingerprint, '\t');
    std::getline(iss, p.publicKey, '\t');
    std::getline(iss, p.shortId, '\t');
    std::getline(iss, p.spiderX, '\t');
    std::getline(iss, p.security, '\t');
    // Backward compatibility
    if (p.encryption.empty()) p.encryption = "none";
    if (p.proxyProtocol.empty()) p.proxyProtocol = "socks";
    if (p.fingerprint.empty()) p.fingerprint = "chrome";
    if (p.spiderX.empty()) p.spiderX = "/";
    return p;
}

static std::string urlDecode(const std::string& src) {
    std::string result;
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%' && i + 2 < src.size()) {
            unsigned int val = 0;
            std::istringstream hex(src.substr(i + 1, 2));
            if (hex >> std::hex >> val) {
                result += static_cast<char>(val);
                i += 2;
                continue;
            }
        } else if (src[i] == '+') {
            result += ' ';
            continue;
        }
        result += src[i];
    }
    return result;
}

static std::string base64Decode(const std::string& encoded) {
    // Simple base64 decode for demonstration
    // In real implementation, use proper base64 library
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=') break;
        auto pos = base64_chars.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

static Profile parseVlessLink(const std::string& link) {
    Profile p;
    p.type = "VLESS";
    p.proxyProtocol = "socks";  // default
    
    // vless://uuid@host:port?params#name
    std::regex vlessRegex(R"(vless://([^@]+)@([^:]+):(\d+)\?([^#]*)#(.+))");
    std::smatch match;
    if (std::regex_match(link, match, vlessRegex)) {
        p.uuid = match[1].str();
        p.address = match[2].str() + ":" + match[3].str();
        p.name = match[5].str();
        
        // Parse query parameters
        std::string params = match[4].str();
        std::istringstream iss(params);
        std::string param;
        while (std::getline(iss, param, '&')) {
            size_t eqPos = param.find('=');
            if (eqPos != std::string::npos) {
                std::string key   = param.substr(0, eqPos);
                std::string value = urlDecode(param.substr(eqPos + 1));

                if (key == "encryption") {
                    p.encryption = value.empty() ? "none" : value;
                } else if (key == "flow") {
                    p.flow = value;
                } else if (key == "security") {
                    p.security = value;
                } else if (key == "sni") {
                    p.sni = value;
                } else if (key == "fp") {
                    p.fingerprint = value;
                } else if (key == "pbk") {
                    p.publicKey = value;
                } else if (key == "sid") {
                    p.shortId = value;
                } else if (key == "spx") {
                    p.spiderX = value.empty() ? "/" : value;
                }
            }
        }
    } else {
        p.name = "Invalid VLESS";
        p.address = "invalid";
    }
    return p;
}

static Profile parseVmessLink(const std::string& link) {
    Profile p;
    p.type = "VMess";
    p.proxyProtocol = "socks";  // default
    
    // vmess://base64json
    size_t pos = link.find("://");
    if (pos != std::string::npos) {
        std::string encoded = link.substr(pos + 3);
        std::string decoded = base64Decode(encoded);
        // Parse JSON-like format: {"ps":"name","add":"host","port":"443","id":"uuid",...}
        
        // Extract name
        size_t psPos = decoded.find("\"ps\":\"");
        if (psPos != std::string::npos) {
            psPos += 6;
            size_t end = decoded.find("\"", psPos);
            p.name = decoded.substr(psPos, end - psPos);
        }
        
        // Extract address and port
        size_t addPos = decoded.find("\"add\":\"");
        if (addPos != std::string::npos) {
            addPos += 7;
            size_t end = decoded.find("\"", addPos);
            std::string host = decoded.substr(addPos, end - addPos);
            size_t portPos = decoded.find("\"port\":");
            if (portPos != std::string::npos) {
                portPos += 7;
                // Skip to the value (could be quoted or not)
                if (decoded[portPos] == '"') portPos++;
                size_t portEnd = decoded.find_first_of("\",", portPos);
                std::string port = decoded.substr(portPos, portEnd - portPos);
                p.address = host + ":" + port;
            }
        }
        
        // Extract UUID
        size_t idPos = decoded.find("\"id\":\"");
        if (idPos != std::string::npos) {
            idPos += 6;
            size_t end = decoded.find("\"", idPos);
            p.uuid = decoded.substr(idPos, end - idPos);
        }
        
        // Extract encryption method
        size_t encPos = decoded.find("\"scy\":\"");
        if (encPos != std::string::npos) {
            encPos += 7;
            size_t end = decoded.find("\"", encPos);
            p.encryption = decoded.substr(encPos, end - encPos);
        }
    } else {
        p.name = "Invalid VMess";
        p.address = "invalid";
    }
    return p;
}

static Profile parseSsLink(const std::string& link) {
    Profile p;
    p.type = "Shadowsocks";
    p.proxyProtocol = "socks";  // default
    
    // ss://method:password@host:port#name or ss://base64(method:password)@host:port#name
    size_t pos = link.find("://");
    if (pos != std::string::npos) {
        std::string encoded = link.substr(pos + 3);
        size_t atPos = encoded.find("@");
        if (atPos != std::string::npos) {
            // Try to decode method:password
            std::string methodPassPart = encoded.substr(0, atPos);
            std::string methodPass = base64Decode(methodPassPart);
            
            // If decode fails or returns same string, use as-is
            if (methodPass == methodPassPart || methodPass.empty()) {
                methodPass = methodPassPart;
            }
            
            size_t colonPos = methodPass.find(":");
            if (colonPos != std::string::npos) {
                p.method = methodPass.substr(0, colonPos);
                p.password = methodPass.substr(colonPos + 1);
            }
            
            // Parse address
            std::string hostPort = encoded.substr(atPos + 1);
            size_t hashPos = hostPort.find("#");
            if (hashPos != std::string::npos) {
                p.name = hostPort.substr(hashPos + 1);
                hostPort = hostPort.substr(0, hashPos);
            } else {
                p.name = "Shadowsocks";
            }
            p.address = hostPort;
        }
    } else {
        p.name = "Invalid SS";
        p.address = "invalid";
    }
    return p;
}

static Profile parseVpnLink(const std::string& link) {
    if (link.find("vless://") == 0) {
        return parseVlessLink(link);
    } else if (link.find("vmess://") == 0) {
        return parseVmessLink(link);
    } else if (link.find("ss://") == 0) {
        return parseSsLink(link);
    } else {
        Profile p;
        p.type = "Unknown";
        p.name = "Unsupported Link";
        p.address = "invalid";
        return p;
    }
}

static void addProfileFromLink(std::vector<Profile>& profiles, Language lang) {
    clearScreen();
    std::string link = inputString(tr(lang, "Enter VPN link: ", "Введите ссылку на VPN: "), lang);
    if (link.empty()) {
        return; // cancelled
    }

    Profile newProfile = parseVpnLink(link);
    if (newProfile.address != "invalid") {
        profiles.push_back(newProfile);
        std::cout << tr(lang, "Profile added from link.", "Профиль добавлен из ссылки.") << "\n";
    } else {
        std::cout << tr(lang, "Invalid or unsupported link format.", "Неверный или неподдерживаемый формат ссылки.") << "\n";
    }
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
}

static void showSettingsScreen(const Settings& settings) {
    clearScreen();
    Language lang = settings.language;
    std::cout << "=== " << tr(lang, "Settings", "Настройки") << " ===\n\n";

    // ── General ──────────────────────────────────────────────────────────────
    std::cout << tr(lang, "--- General ---", "--- Основные ---") << "\n";
    std::cout << " 1. " << tr(lang, "Auto-start xray-core", "Автостарт xray-core") << ": "
              << (settings.autoStart ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
    std::cout << " 2. " << tr(lang, "Language", "Язык") << ": " << languageName(settings.language) << "\n";
    std::cout << " 3. " << tr(lang, "Log level (1-debug … 5-off)", "Уровень лога (1-debug … 5-off)") << ": ";
    switch (settings.logLevel) {
        case 1: std::cout << "1 (debug)";   break;
        case 2: std::cout << "2 (info)";    break;
        case 3: std::cout << "3 (warning)"; break;
        case 4: std::cout << "4 (error)";   break;
        case 5: std::cout << "5 (none)";    break;
        default: std::cout << settings.logLevel; break;
    }
    std::cout << "\n";
    std::cout << " 4. " << tr(lang, "xray-core folder", "Папка xray-core") << ": " << settings.xrayCoreDir << "\n";

    // ── Proxy ─────────────────────────────────────────────────────────────────
    std::cout << "\n" << tr(lang, "--- Proxy ---", "--- Прокси ---") << "\n";
    std::cout << " 5. " << tr(lang, "SOCKS5 proxy port", "Порт SOCKS5 прокси") << ": " << settings.proxyPort << "\n";
    std::cout << " 6. " << tr(lang, "HTTP proxy port (0 = disabled)", "Порт HTTP прокси (0 = откл)") << ": " << settings.httpProxyPort << "\n";
    std::cout << " 7. " << tr(lang, "DNS servers", "DNS серверы") << ": " << settings.dnsServers << "\n";

    // ── Tunnel / TUN ──────────────────────────────────────────────────────────
    std::cout << "\n" << tr(lang, "--- TUN Tunnel ---", "--- TUN туннель ---") << "\n";
    std::cout << " 8. " << tr(lang, "Tunnel subnet (TUN interface CIDR)", "Подсеть туннеля (CIDR TUN-интерфейса)") << ": " << settings.tunnelSubnet << "\n";
    std::cout << " 9. " << tr(lang, "TUN interface name (auto = OS chooses)", "Имя TUN интерфейса (auto = выбирает ОС)") << ": " << settings.tunInterface << "\n";
    std::cout << "10. " << tr(lang, "Kill-switch (block traffic if VPN drops)", "Kill-switch (блок трафика при обрыве VPN)") << ": "
              << (settings.killSwitch ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
    std::cout << "11. " << tr(lang, "Route IPv6 through tunnel", "Маршрутизация IPv6 через туннель") << ": "
              << (settings.enableIPv6 ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
    std::cout << "12. " << tr(lang, "Split-tunnel (bypass local/CN traffic)", "Split-tunnel (обход локального/CN трафика)") << ": "
              << (settings.splitTunnel ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";

    std::cout << "\n" << tr(lang, "Type a number to change the option, or press 0 to return.",
                                 "Введите цифру для изменения опции или 0 для возвращения.") << "\n";
}

static void printProfileEditMenu(const Profile& profile, Language lang) {
    clearScreen();
    std::cout << tr(lang, "Editing profile: ", "Редактирование профиля: ") << profile.name << "\n\n";
    std::cout << "1.  " << tr(lang, "Name", "Имя") << ": " << profile.name << "\n";
    std::cout << "2.  " << tr(lang, "Type", "Тип") << ": " << profile.type << "\n";
    std::cout << "3.  " << tr(lang, "Address", "Адрес") << ": " << profile.address << "\n";
    std::cout << "4.  " << tr(lang, "UUID", "UUID") << ": " << profile.uuid << "\n";
    std::cout << "5.  " << tr(lang, "Encryption", "Шифрование") << ": " << profile.encryption << "\n";
    std::cout << "6.  " << tr(lang, "Flow", "Flow") << ": " << profile.flow << "\n";
    std::cout << "7.  " << tr(lang, "Method", "Метод") << ": " << profile.method << "\n";
    std::cout << "8.  " << tr(lang, "Password", "Пароль") << ": " << profile.password << "\n";
    std::cout << "9.  " << tr(lang, "Proxy Protocol", "Протокол прокси") << " (socks/http): " << profile.proxyProtocol << "\n";
    std::cout << "10. " << tr(lang, "Security", "Безопасность") << " (reality/tls): " << profile.security << "\n";
    std::cout << "11. " << tr(lang, "SNI", "SNI") << ": " << profile.sni << "\n";
    std::cout << "12. " << tr(lang, "Fingerprint", "Отпечаток") << ": " << profile.fingerprint << "\n";
    std::cout << "13. " << tr(lang, "Public Key (Reality)", "Публичный ключ (Reality)") << ": " << profile.publicKey << "\n";
    std::cout << "14. " << tr(lang, "Short ID (Reality)", "Short ID (Reality)") << ": " << profile.shortId << "\n";
    std::cout << "15. " << tr(lang, "Spider X (Reality)", "Spider X (Reality)") << ": " << profile.spiderX << "\n";
    std::cout << "\n" << tr(lang, "Type a number to change the option, or press 0 to return.", "Введите цифру для изменения опции или 0 для возвращения.") << "\n";
}

static void editProfile(Profile& profile, Language lang) {
    printProfileEditMenu(profile, lang);

    // Multi-digit input buffer for options 10-15
    std::string numBuf;
    while (true) {
        int key = readKey();
        if (key == '0' && numBuf.empty()) break;

        // Accumulate digits for two-digit options
        if (key >= '0' && key <= '9') {
            numBuf += (char)key;
            // If single digit and can't be start of two-digit option, process immediately
            if (numBuf.size() == 1 && numBuf[0] >= '1' && numBuf[0] <= '9') {
                // Wait briefly for possible second digit — check if a two-digit option starts with this
                // We handle this by treating input: if next key is Enter or non-digit, use numBuf
                // Simple approach: single key = single digit option (1-9), two chars needed for 10-15
                // Actually readKey reads one key at a time, so we just process single digits immediately
                // unless user pressed 1 which could be start of 10-15
                if (numBuf[0] != '1') {
                    // 2-9: process immediately
                } else {
                    // Could be '1' alone or start of '10'-'15', wait for one more key
                    int next = readKey();
                    if (next >= '0' && next <= '5') {
                        numBuf += (char)next;
                    } else if (next == '\n' || next == '\r') {
                        // '1' alone confirmed
                    } else {
                        // ignore next key, process '1'
                    }
                }
            }
        } else if (key == '\n' || key == '\r') {
            if (numBuf.empty()) { printProfileEditMenu(profile, lang); continue; }
        }

        int option = 0;
        if (!numBuf.empty()) {
            try { option = std::stoi(numBuf); } catch (...) {}
        }
        numBuf.clear();

        if (option == 0) { printProfileEditMenu(profile, lang); continue; }

        if (option == 1) {
            std::string v = inputString(tr(lang, "Enter new name: ", "Введите новое имя: "), lang);
            if (!v.empty()) profile.name = v;
        } else if (option == 2) {
            std::string v = inputString(tr(lang, "Enter type (VLESS, VMess, Trojan, Shadowsocks): ", "Введите тип (VLESS, VMess, Trojan, Shadowsocks): "), lang);
            if (!v.empty()) profile.type = v;
        } else if (option == 3) {
            std::string v = inputString(tr(lang, "Enter address (host:port): ", "Введите адрес (host:port): "), lang);
            if (!v.empty()) profile.address = v;
        } else if (option == 4) {
            std::string v = inputString(tr(lang, "Enter UUID: ", "Введите UUID: "), lang);
            if (!v.empty()) profile.uuid = v;
        } else if (option == 5) {
            std::string v = inputString(tr(lang, "Enter encryption (none, aes-128-gcm, chacha20-poly1305): ", "Введите шифрование (none, aes-128-gcm, chacha20-poly1305): "), lang);
            if (!v.empty()) profile.encryption = v;
        } else if (option == 6) {
            std::string v = inputString(tr(lang, "Enter flow (xtls-rprx-vision or empty): ", "Введите flow (xtls-rprx-vision или пусто): "), lang);
            profile.flow = v;
        } else if (option == 7) {
            std::string v = inputString(tr(lang, "Enter method: ", "Введите метод: "), lang);
            profile.method = v;
        } else if (option == 8) {
            std::string v = inputString(tr(lang, "Enter password: ", "Введите пароль: "), lang);
            profile.password = v;
        } else if (option == 9) {
            std::string v = inputString(tr(lang, "Enter proxy protocol (socks or http): ", "Введите протокол прокси (socks или http): "), lang);
            if (!v.empty()) profile.proxyProtocol = v;
        } else if (option == 10) {
            std::string v = inputString(tr(lang, "Enter security (reality/tls or empty): ", "Введите тип безопасности (reality/tls или пусто): "), lang);
            profile.security = v;
        } else if (option == 11) {
            std::string v = inputString(tr(lang, "Enter SNI (server name): ", "Введите SNI (имя сервера): "), lang);
            profile.sni = v;
        } else if (option == 12) {
            std::string v = inputString(tr(lang, "Enter fingerprint (chrome/firefox/safari/...): ", "Введите отпечаток (chrome/firefox/safari/...): "), lang);
            if (!v.empty()) profile.fingerprint = v;
        } else if (option == 13) {
            std::string v = inputString(tr(lang, "Enter Reality public key: ", "Введите публичный ключ Reality: "), lang);
            profile.publicKey = v;
        } else if (option == 14) {
            std::string v = inputString(tr(lang, "Enter Reality short ID: ", "Введите short ID Reality: "), lang);
            profile.shortId = v;
        } else if (option == 15) {
            std::string v = inputString(tr(lang, "Enter Spider X (default /): ", "Введите Spider X (по умолчанию /): "), lang);
            profile.spiderX = v.empty() ? "/" : v;
        }
        printProfileEditMenu(profile, lang);
    }
}

static void deleteProfile(std::vector<Profile>& profiles, size_t index, Language lang) {
    clearScreen();
    std::cout << tr(lang, "Delete profile: ", "Удалить профиль: ") << profiles[index].name << "?\n";
    std::cout << tr(lang, "Press Y to confirm, any other key to cancel.", "Нажмите Y для подтверждения, любую другую клавишу для отмены.") << "\n";
    int key = readKey();
    if (key == 'y' || key == 'Y') {
        profiles.erase(profiles.begin() + index);
        std::cout << tr(lang, "Profile deleted.", "Профиль удалён.") << "\n";
    } else {
        std::cout << tr(lang, "Cancelled.", "Отменено.") << "\n";
    }
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
}

static void addProfileManually(std::vector<Profile>& profiles, Language lang) {
    clearScreen();
    Profile newProfile;

    newProfile.name = inputString(tr(lang, "Enter profile name: ", "Введите имя профиля: "), lang);
    if (newProfile.name.empty()) return;

    newProfile.type = inputString(tr(lang, "Enter profile type (e.g., VMess, VLESS, Trojan, Shadowsocks): ", "Введите тип профиля (например, VMess, VLESS, Trojan, Shadowsocks): "), lang);
    if (newProfile.type.empty()) return;

    newProfile.address = inputString(tr(lang, "Enter address (host:port): ", "Введите адрес (host:port): "), lang);
    if (newProfile.address.empty()) return;

    newProfile.uuid = inputString(tr(lang, "Enter UUID (optional): ", "Введите UUID (опционально): "), lang);
    newProfile.encryption = inputString(tr(lang, "Enter encryption (optional, default: none): ", "Введите шифрование (опционально, по умолчанию: none): "), lang);
    if (newProfile.encryption.empty()) newProfile.encryption = "none";
    
    newProfile.flow = inputString(tr(lang, "Enter flow (optional, e.g., xtls-rprx-vision): ", "Введите flow (опционально, например, xtls-rprx-vision): "), lang);
    newProfile.method = inputString(tr(lang, "Enter method (optional): ", "Введите метод (опционально): "), lang);
    newProfile.password = inputString(tr(lang, "Enter password (optional): ", "Введите пароль (опционально): "), lang);
    
    newProfile.proxyProtocol = inputString(tr(lang, "Enter default proxy protocol (socks or http, default: socks): ", "Введите протокол прокси по умолчанию (socks или http, по умолчанию: socks): "), lang);
    if (newProfile.proxyProtocol.empty()) newProfile.proxyProtocol = "socks";

    profiles.push_back(newProfile);

    std::cout << tr(lang, "Profile added manually.", "Профиль добавлен вручную.") << "\n";
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
}

static void showProfilesMenu(const std::vector<Profile>& profiles, Language lang) {
    clearScreen();
    std::cout << "=== " << tr(lang, "Profiles", "Профили") << " ===\n\n";
    if (profiles.empty()) {
        std::cout << tr(lang, "No profiles available.", "Нет доступных профилей.") << "\n";
    } else {
        for (size_t i = 0; i < profiles.size(); ++i) {
            std::cout << i + 1 << ". " << profiles[i].name
                      << " (" << profiles[i].type << ") @ " << profiles[i].address << "\n";
        }
    }
    std::cout << "\n" << tr(lang, "Type profile number to edit/delete, or:", "Введите номер профиля для редактирования/удаления, или:") << "\n";
    std::cout << tr(lang, "A. Add from link", "A. Добавить из ссылки") << "\n";
    std::cout << tr(lang, "M. Add manually", "M. Добавить вручную") << "\n";
    std::cout << tr(lang, "0. Back", "0. Назад") << "\n";
}

void showProfiles(const std::vector<Profile>& profiles, Language lang) {
    showProfilesMenu(profiles, lang);
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
}

void editProfiles(std::vector<Profile>& profiles, Language lang) {
    while (true) {
        showProfilesMenu(profiles, lang);
        int key = readKey();
        if (key == 3) continue; // ignore Ctrl+C
        if (key == '0') {
            break;
        } else if (key >= '1' && key <= '0' + static_cast<int>(profiles.size())) {
            size_t index = key - '1';
            clearScreen();
            std::cout << tr(lang, "Profile: ", "Профиль: ") << profiles[index].name << "\n";
            std::cout << tr(lang, "E. Edit", "E. Редактировать") << "\n";
            std::cout << tr(lang, "D. Delete", "D. Удалить") << "\n";
            std::cout << tr(lang, "V. View config", "V. Просмотр конфига") << "\n";
            std::cout << tr(lang, "0. Back", "0. Назад") << "\n";
            int subKey = readKey();
            if (subKey == 'e' || subKey == 'E') {
                editProfile(profiles[index], lang);
            } else if (subKey == 'd' || subKey == 'D') {
                deleteProfile(profiles, index, lang);
            } else if (subKey == 'v' || subKey == 'V') {
                clearScreen();
                std::cout << tr(lang, "Config for profile: ", "Конфиг для профиля: ") << profiles[index].name << "\n\n";
                std::string config = generateConfig(profiles[index]);
                std::cout << config << "\n";
                pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
            }
        } else if (key == 'a' || key == 'A') {
            addProfileFromLink(profiles, lang);
        } else if (key == 'm' || key == 'M') {
            addProfileManually(profiles, lang);
        }
    }
}

void editSettings(Settings& settings) {
    auto readOption = [&]() -> int {
        // Reads a 1- or 2-digit option number, similar to editProfile.
        std::string buf;
        while (true) {
            int k = readKey();
            if (k == 3) return -1;   // Ctrl+C → ignore
            if (k == '0' && buf.empty()) return 0;
            if (k >= '0' && k <= '9') {
                buf += (char)k;
                if (buf.size() == 1 && buf[0] == '1') {
                    // Could be '1' alone or start of '10'-'12'
                    int next = readKey();
                    if (next >= '0' && next <= '2') {
                        buf += (char)next;
                    } else if (next == '\n' || next == '\r') {
                        // '1' confirmed
                    }
                    // else: ignore extra key, use '1'
                }
                try { return std::stoi(buf); } catch (...) { return -1; }
            }
            if (k == '\n' || k == '\r') return -1;
        }
    };

    Language& lang = settings.language;

    while (true) {
        showSettingsScreen(settings);
        int option = readOption();
        if (option == -1) continue;
        if (option == 0) break;

        clearScreen();
        if (option == 1) {
            settings.autoStart = !settings.autoStart;
        } else if (option == 2) {
            settings.language = (lang == Language::EN ? Language::RU : Language::EN);
        } else if (option == 3) {
            settings.logLevel = (settings.logLevel % 5) + 1;
        } else if (option == 4) {
            std::string path = inputString(
                tr(lang,
                   "Enter xray-core folder path (current: " + settings.xrayCoreDir + "): ",
                   "Введите путь к папке xray-core (текущий: " + settings.xrayCoreDir + "): "),
                lang);
            if (!path.empty()) settings.xrayCoreDir = path;
        } else if (option == 5) {
            std::string portStr = inputString(
                tr(lang,
                   "SOCKS5 proxy port (current: " + std::to_string(settings.proxyPort) + ", 1-65535): ",
                   "Порт SOCKS5 прокси (текущий: " + std::to_string(settings.proxyPort) + ", 1-65535): "),
                lang);
            if (!portStr.empty()) {
                try {
                    int p = std::stoi(portStr);
                    if (p >= 1 && p <= 65535) settings.proxyPort = p;
                    else { std::cout << tr(lang, "Invalid port.", "Неверный порт.") << "\n"; pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша...")); }
                } catch (...) { std::cout << tr(lang, "Invalid input.", "Неверный ввод.") << "\n"; pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша...")); }
            }
        } else if (option == 6) {
            std::string portStr = inputString(
                tr(lang,
                   "HTTP proxy port (current: " + std::to_string(settings.httpProxyPort) + ", 0 to disable, 1-65535): ",
                   "Порт HTTP прокси (текущий: " + std::to_string(settings.httpProxyPort) + ", 0 = откл, 1-65535): "),
                lang);
            if (!portStr.empty()) {
                try {
                    int p = std::stoi(portStr);
                    if (p == 0 || (p >= 1 && p <= 65535)) settings.httpProxyPort = p;
                    else { std::cout << tr(lang, "Invalid port.", "Неверный порт.") << "\n"; pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша...")); }
                } catch (...) { std::cout << tr(lang, "Invalid input.", "Неверный ввод.") << "\n"; pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша...")); }
            }
        } else if (option == 7) {
            std::string dns = inputString(
                tr(lang,
                   "DNS servers (current: " + settings.dnsServers + ", comma-separated, e.g. 8.8.8.8,1.1.1.1): ",
                   "DNS серверы (текущие: " + settings.dnsServers + ", через запятую, напр. 8.8.8.8,1.1.1.1): "),
                lang);
            if (!dns.empty()) settings.dnsServers = dns;
        } else if (option == 8) {
            std::string sub = inputString(
                tr(lang,
                   "Tunnel subnet CIDR (current: " + settings.tunnelSubnet + ", e.g. 10.8.0.1/30): ",
                   "CIDR подсети туннеля (текущая: " + settings.tunnelSubnet + ", напр. 10.8.0.1/30): "),
                lang);
            if (!sub.empty()) settings.tunnelSubnet = sub;
        } else if (option == 9) {
            std::string iface = inputString(
                tr(lang,
                   "TUN interface name (current: " + settings.tunInterface + ", 'auto' = OS chooses): ",
                   "Имя TUN интерфейса (текущее: " + settings.tunInterface + ", 'auto' = выбирает ОС): "),
                lang);
            if (!iface.empty()) settings.tunInterface = iface;
        } else if (option == 10) {
            settings.killSwitch = !settings.killSwitch;
            std::cout << tr(lang, "Kill-switch: ", "Kill-switch: ")
                      << (settings.killSwitch ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
            pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
        } else if (option == 11) {
            settings.enableIPv6 = !settings.enableIPv6;
            std::cout << tr(lang, "IPv6 tunnel: ", "IPv6 туннель: ")
                      << (settings.enableIPv6 ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
            pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
        } else if (option == 12) {
            settings.splitTunnel = !settings.splitTunnel;
            std::cout << tr(lang, "Split-tunnel: ", "Split-tunnel: ")
                      << (settings.splitTunnel ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
            pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
        }
    }
}

void saveProfiles(const std::vector<Profile>& profiles) {
    std::string data;
    for (const auto& profile : profiles) {
        data += serializeProfile(profile);
    }
    std::string encrypted = encryptDecrypt(data, "xray_launcher_key");
    std::string path = getDataDir() + "/profiles.dat";
    std::ofstream file(path, std::ios::binary);
    if (file.is_open()) {
        file.write(encrypted.c_str(), encrypted.size());
    }
}

void loadProfiles(std::vector<Profile>& profiles) {
    std::string path = getDataDir() + "/profiles.dat";
    if (!fs::exists(path)) return;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return;
    std::string encrypted((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string data = encryptDecrypt(encrypted, "xray_launcher_key");
    std::istringstream iss(data);
    std::string line;
    profiles.clear();
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            profiles.push_back(deserializeProfile(line));
        }
    }
}

// ── Per-app proxy list persistence ────────────────────────────────────────

void saveAppList(const Settings& settings) {
    std::string path = getDataDir() + "/applist.dat";
    std::ofstream f(path);
    if (!f) return;
    for (const auto& e : settings.appList) {
        // Escape tab in name/command just in case
        std::string name    = e.name;
        std::string command = e.command;
        // Replace any literal tabs with spaces
        for (auto& c : name)    if (c == '\t') c = ' ';
        for (auto& c : command) if (c == '\t') c = ' ';
        f << name << "\t" << command << "\n";
    }
}

void loadAppList(Settings& settings) {
    std::string path = getDataDir() + "/applist.dat";
    if (!fs::exists(path)) return;
    std::ifstream f(path);
    if (!f) return;
    settings.appList.clear();
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        size_t tab = line.find('\t');
        if (tab == std::string::npos) continue;
        AppEntry e;
        e.name    = line.substr(0, tab);
        e.command = line.substr(tab + 1);
        settings.appList.push_back(e);
    }
}

void saveSettings(const Settings& settings) {
    std::string path = getDataDir() + "/settings.dat";
    std::ofstream file(path);
    if (!file.is_open()) return;
    file << "autoStart="     << (settings.autoStart     ? "1" : "0") << "\n";
    file << "useProxy="      << (settings.useProxy       ? "1" : "0") << "\n";
    file << "logLevel="      << settings.logLevel        << "\n";
    file << "language="      << (settings.language == Language::RU ? "RU" : "EN") << "\n";
    file << "xrayCoreDir="   << settings.xrayCoreDir    << "\n";
    file << "systemVpnMode=" << (settings.systemVpnMode ? "1" : "0") << "\n";
    file << "dnsServers="    << settings.dnsServers      << "\n";
    file << "proxyPort="     << settings.proxyPort       << "\n";
    // Tunnel / TUN settings
    file << "tunnelSubnet="  << settings.tunnelSubnet    << "\n";
    file << "tunInterface="  << settings.tunInterface    << "\n";
    file << "killSwitch="    << (settings.killSwitch     ? "1" : "0") << "\n";
    file << "httpProxyPort=" << settings.httpProxyPort   << "\n";
    file << "enableIPv6="    << (settings.enableIPv6     ? "1" : "0") << "\n";
    file << "splitTunnel="   << (settings.splitTunnel    ? "1" : "0") << "\n";
}

void loadSettings(Settings& settings) {
    std::string path = getDataDir() + "/settings.dat";
    if (!fs::exists(path)) return;
    std::ifstream file(path);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if (key == "autoStart")          settings.autoStart     = (val == "1");
        else if (key == "useProxy")      settings.useProxy      = (val == "1");
        else if (key == "logLevel") {
            try { settings.logLevel = std::stoi(val); } catch (...) {}
        }
        else if (key == "language")      settings.language      = (val == "RU" ? Language::RU : Language::EN);
        else if (key == "xrayCoreDir")   settings.xrayCoreDir   = val;
        else if (key == "systemVpnMode") settings.systemVpnMode = (val == "1");
        else if (key == "dnsServers")    settings.dnsServers    = val;
        else if (key == "proxyPort") {
            try { int p = std::stoi(val); if (p >= 1 && p <= 65535) settings.proxyPort = p; } catch (...) {}
        }
        // Tunnel / TUN settings
        else if (key == "tunnelSubnet")  settings.tunnelSubnet  = val;
        else if (key == "tunInterface")  settings.tunInterface  = val;
        else if (key == "killSwitch")    settings.killSwitch    = (val == "1");
        else if (key == "httpProxyPort") {
            try { int p = std::stoi(val); if (p >= 0 && p <= 65535) settings.httpProxyPort = p; } catch (...) {}
        }
        else if (key == "enableIPv6")    settings.enableIPv6    = (val == "1");
        else if (key == "splitTunnel")   settings.splitTunnel   = (val == "1");
    }
}

// ── Per-app proxy UI ───────────────────────────────────────────────────────

static void printAppProxyMenu(const Settings& settings) {
    Language lang = settings.language;
    clearScreen();
    std::cout << "=== " << tr(lang, "Per-app proxy", "Прокси для приложений") << " ===\n\n";

    if (!settings.appList.empty()) {
        std::cout << tr(lang, "Configured apps:", "Настроенные приложения:") << "\n";
        for (size_t i = 0; i < settings.appList.size(); ++i) {
            std::cout << "  " << i + 1 << ". "
                      << settings.appList[i].name << "\n"
                      << "       " << settings.appList[i].command << "\n";
        }
        std::cout << "\n";
    } else {
        std::cout << tr(lang, "No apps configured yet.", "Приложения ещё не добавлены.") << "\n\n";
    }

    std::cout << tr(lang,
        "A. Add new app\n"
        "L. Launch an app through proxy\n"
        "D. Delete an app\n"
        "0. Back\n",
        "A. Добавить приложение\n"
        "L. Запустить приложение через прокси\n"
        "D. Удалить приложение\n"
        "0. Назад\n");
}

// Show the per-app proxy manager.
// proxyPort and httpProxyPort are the currently active proxy ports
// (pass 0 if xray is not running — launch will warn the user).
void editAppProxyList(Settings& settings, int proxyPort, int httpProxyPort) {
    Language lang = settings.language;
    while (true) {
        printAppProxyMenu(settings);
        int key = readKey();
        if (key == 3) continue;
        if (key == '0') break;

        if (key == 'a' || key == 'A') {
            // ── Add entry ──────────────────────────────────────────────────
            clearScreen();
            std::cout << tr(lang,
                "Add app to per-app proxy list.\n"
                "Enter a display name and the command (full path or shell command).\n",
                "Добавить приложение в список прокси.\n"
                "Введите имя и команду (полный путь или команда shell).\n") << "\n";

            std::string name = inputString(tr(lang, "Display name: ", "Отображаемое имя: "), lang);
            if (name.empty()) continue;
            std::string cmd  = inputString(tr(lang, "Command (e.g. /usr/bin/firefox): ", "Команда (например /usr/bin/firefox): "), lang);
            if (cmd.empty()) continue;

            AppEntry e;
            e.name    = name;
            e.command = cmd;
            settings.appList.push_back(e);
            saveAppList(settings);
            std::cout << tr(lang, "Added.", "Добавлено.") << "\n";
            pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));

        } else if (key == 'l' || key == 'L') {
            // ── Launch ─────────────────────────────────────────────────────
            if (settings.appList.empty()) {
                clearScreen();
                std::cout << tr(lang, "No apps configured. Add one first.", "Нет приложений. Сначала добавьте.") << "\n";
                pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
                continue;
            }
            if (proxyPort <= 0) {
                clearScreen();
                std::cout << tr(lang,
                    "xray proxy is not running. Start it first (Launch xray-core > proxy mode).",
                    "Прокси xray не запущен. Сначала запустите xray-core в режиме прокси.") << "\n";
                pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
                continue;
            }
            clearScreen();
            std::cout << tr(lang, "Select app to launch:", "Выберите приложение для запуска:") << "\n\n";
            for (size_t i = 0; i < settings.appList.size(); ++i) {
                std::cout << "  " << i + 1 << ". " << settings.appList[i].name
                          << "  [" << settings.appList[i].command << "]\n";
            }
            std::cout << "\n" << tr(lang, "Press number (1-9) or 0 to cancel: ", "Нажмите цифру (1-9) или 0 для отмены: ");
            int sel = readKey();
            if (sel >= '1' && sel <= '0' + static_cast<int>(settings.appList.size())) {
                size_t idx = sel - '1';
                launchAppThroughProxy(settings.appList[idx].command, proxyPort, httpProxyPort, lang);
            }

        } else if (key == 'd' || key == 'D') {
            // ── Delete ─────────────────────────────────────────────────────
            if (settings.appList.empty()) {
                clearScreen();
                std::cout << tr(lang, "Nothing to delete.", "Нечего удалять.") << "\n";
                pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
                continue;
            }
            clearScreen();
            std::cout << tr(lang, "Select app to delete:", "Выберите приложение для удаления:") << "\n\n";
            for (size_t i = 0; i < settings.appList.size(); ++i) {
                std::cout << "  " << i + 1 << ". " << settings.appList[i].name << "\n";
            }
            std::cout << "\n" << tr(lang, "Press number (1-9) or 0 to cancel: ", "Нажмите цифру (1-9) или 0 для отмены: ");
            int sel = readKey();
            if (sel >= '1' && sel <= '0' + static_cast<int>(settings.appList.size())) {
                size_t idx = sel - '1';
                std::cout << "\n" << tr(lang, "Delete: ", "Удалить: ") << settings.appList[idx].name
                          << tr(lang, "? (Y/N) ", "? (Y/N) ");
                int confirm = readKey();
                if (confirm == 'y' || confirm == 'Y') {
                    settings.appList.erase(settings.appList.begin() + idx);
                    saveAppList(settings);
                    std::cout << "\n" << tr(lang, "Deleted.", "Удалено.") << "\n";
                    pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
                }
            }
        }
    }
}
