#ifndef VL2_SETTINGS_H
#define VL2_SETTINGS_H

#include <string>

struct Profile {
    std::string name;
    std::string type;
    std::string address;
    std::string uuid = "";
    std::string encryption = "none";
    std::string flow = "";
    std::string method = "";
    std::string password = "";
    std::string proxyProtocol = "socks";  // "socks" or "http"
    // TLS / Reality settings (used for VLESS+Reality, VMess+TLS, Trojan)
    std::string sni = "";
    std::string fingerprint = "chrome";
    std::string publicKey = "";
    std::string shortId = "";
    std::string spiderX = "/";
    std::string security = "";   // "reality", "tls", or ""
};

enum class Language {
    EN,
    RU
};

std::string tr(Language lang, const std::string& en, const std::string& ru);
std::string languageName(Language lang);

struct Settings {
    bool autoStart = false;
    bool useProxy = true;
    int logLevel = 2;
    Language language = Language::EN;
    std::string xrayCoreDir = "./xray";
    bool systemVpnMode = false;
    std::string dnsServers = "8.8.8.8,8.8.4.4";
    int proxyPort = 1080;   // local inbound port for SOCKS/HTTP/tunnel
};

#endif // VL2_SETTINGS_H
