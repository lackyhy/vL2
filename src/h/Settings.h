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
    std::string dnsServers = "8.8.8.8,1.1.1.1";
    int proxyPort = 1080;   // local inbound port for SOCKS/HTTP/tunnel

    // ── Tunnel / TUN interface settings ──────────────────────────────────────
    // IP address assigned to the TUN interface (CIDR notation).
    // Xray creates the interface automatically when tun inbound is used.
    std::string tunnelSubnet = "10.8.0.1/30";
    // Interface name hint ("auto" lets xray/OS choose, e.g. utun5, tun0).
    std::string tunInterface = "auto";
    // Kill-switch: block all non-VPN traffic when xray-core is not running.
    bool killSwitch = false;
    // Secondary HTTP proxy port (0 = disabled, only SOCKS is used).
    int httpProxyPort = 8080;
    // Route IPv6 traffic through the tunnel as well.
    bool enableIPv6 = false;
    // Split-tunnel: when false, only route all traffic through VPN.
    bool splitTunnel = false;
};

#endif // VL2_SETTINGS_H
