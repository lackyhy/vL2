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
#include <pwd.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

extern bool g_headlessMode;

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
    return generateConfig(profile, tunnelMode, proxyProtocol, port, false, "", "");
}

std::string generateConfig(const Profile& profile, bool tunnelMode, const std::string& proxyProtocol, int port,
                           bool socks5Auth, const std::string& socks5Username, const std::string& socks5Password) {
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
        if (socks5Auth && !socks5Username.empty()) {
            oss << R"(
        "auth": "password",
        "accounts": [
          { "user": ")" << socks5Username << R"(", "pass": ")" << socks5Password << R"(" }
        ]
)";
        } else {
            oss << R"(
        "auth": "noauth"
)";
        }
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
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        if (std::regex_match(profile.address, match, addrRegex)) {
            std::string host       = match[1].str();
            std::string portStr    = match[2].str();
            std::string uuid       = profile.uuid.empty() ? "fc1e5950-d7eb-4032-a22f-67031e41c8b6" : profile.uuid;
            std::string encryption = profile.encryption.empty() ? "none" : profile.encryption;
            std::string flow       = profile.flow;
            std::string security   = profile.security;   // "reality", "tls", or ""
            std::string sni        = profile.sni.empty() ? host : profile.sni;
            std::string fp         = profile.fingerprint.empty() ? "chrome" : profile.fingerprint;
            std::string pubKey     = profile.publicKey;
            std::string shortId    = profile.shortId;
            std::string spiderX    = profile.spiderX.empty() ? "/" : profile.spiderX;

            oss << R"(
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": ")" << host << R"(",
            "port": )" << portStr << R"(,
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
        "security": ")" << (security.empty() ? "none" : security) << R"(")"
;
            if (security == "reality") {
                oss << R"(,
        "realitySettings": {
          "serverName": ")" << sni << R"(",
          "fingerprint": ")" << fp << R"(",
          "publicKey": ")" << pubKey << R"(",
          "shortId": ")" << shortId << R"(",
          "spiderX": ")" << spiderX << R"("
        })";
            } else if (security == "tls") {
                oss << R"(,
        "tlsSettings": {
          "serverName": ")" << sni << R"(",
          "fingerprint": ")" << fp << R"(",
          "allowInsecure": false
        })";
            }
            oss << R"(
      })";
            if (flow.empty()) {
                oss << R"(,
      "mux": { "enabled": true, "concurrency": 8 }
)";
            } else {
                oss << "\n";
            }
        }
    } else if (profile.type == "VMess") {
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        std::string host    = "example.com";
        std::string portStr = "443";
        if (std::regex_match(profile.address, match, addrRegex)) {
            host    = match[1].str();
            portStr = match[2].str();
        }
        std::string uuid       = profile.uuid.empty() ? "uuid" : profile.uuid;
        std::string encryption = profile.encryption.empty() ? "auto" : profile.encryption;
        std::string security   = profile.security;
        std::string sni        = profile.sni.empty() ? host : profile.sni;
        std::string fp         = profile.fingerprint.empty() ? "chrome" : profile.fingerprint;

        oss << R"(
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": ")" << host << R"(",
            "port": )" << portStr << R"(,
            "users": [
              {
                "id": ")" << uuid << R"(",
                "security": ")" << encryption << R"(",
                "alterId": 0
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": ")" << (security.empty() ? "none" : security) << R"(")"
;
        if (security == "tls") {
            oss << R"(,
        "tlsSettings": {
          "serverName": ")" << sni << R"(",
          "fingerprint": ")" << fp << R"(",
          "allowInsecure": false
        })";
        }
        oss << R"(
      },
      "mux": { "enabled": true, "concurrency": 8 }
)";
    } else if (profile.type == "Shadowsocks") {
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        std::string host    = "example.com";
        std::string portStr = "8388";
        if (std::regex_match(profile.address, match, addrRegex)) {
            host    = match[1].str();
            portStr = match[2].str();
        }
        std::string method   = profile.method.empty() ? "aes-256-gcm" : profile.method;
        std::string password = profile.password;

        oss << R"(
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": ")" << host << R"(",
            "port": )" << portStr << R"(,
            "method": ")" << method << R"(",
            "password": ")" << password << R"("
          }
        ]
      }
)";
    } else {
        oss << R"(
      "protocol": "freedom"
)";
    }

    oss << R"(
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
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

// ── Helper: emit only the outbound block (protocol-specific JSON) ──────────
// Used by both generateConfig and generateTunConfig to avoid duplication.
static void appendOutbound(std::ostringstream& oss, const Profile& profile) {
    if (profile.type == "VLESS") {
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        if (!std::regex_match(profile.address, match, addrRegex)) return;

        std::string host       = match[1].str();
        std::string portStr    = match[2].str();
        std::string uuid       = profile.uuid.empty() ? "fc1e5950-d7eb-4032-a22f-67031e41c8b6" : profile.uuid;
        std::string encryption = profile.encryption.empty() ? "none" : profile.encryption;
        std::string flow       = profile.flow;
        std::string security   = profile.security;
        std::string sni        = profile.sni.empty() ? host : profile.sni;
        std::string fp         = profile.fingerprint.empty() ? "chrome" : profile.fingerprint;
        std::string pubKey     = profile.publicKey;
        std::string shortId    = profile.shortId;
        std::string spiderX    = profile.spiderX.empty() ? "/" : profile.spiderX;

        oss << R"(
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": ")" << host << R"(",
          "port": )" << portStr << R"(,
          "users": [{
            "id": ")" << uuid << R"(",
            "encryption": ")" << encryption << R"(")"
            << (flow.empty() ? "" : ",\n            \"flow\": \"" + flow + "\"")
            << R"(
          }]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": ")" << (security.empty() ? "none" : security) << R"(")"
;
        if (security == "reality") {
            oss << R"(,
        "realitySettings": {
          "serverName": ")" << sni << R"(",
          "fingerprint": ")" << fp << R"(",
          "publicKey": ")" << pubKey << R"(",
          "shortId": ")" << shortId << R"(",
          "spiderX": ")" << spiderX << R"("
        })";
        } else if (security == "tls") {
            oss << R"(,
        "tlsSettings": {
          "serverName": ")" << sni << R"(",
          "fingerprint": ")" << fp << R"(",
          "allowInsecure": false
        })";
        }
        oss << R"(
      })";
        if (flow.empty()) {
            oss << R"(,
      "mux": { "enabled": true, "concurrency": 8 })";
        }
    } else if (profile.type == "VMess") {
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        std::string host    = "example.com";
        std::string portStr = "443";
        if (std::regex_match(profile.address, match, addrRegex)) {
            host    = match[1].str();
            portStr = match[2].str();
        }
        std::string uuid       = profile.uuid.empty() ? "uuid" : profile.uuid;
        std::string encryption = profile.encryption.empty() ? "auto" : profile.encryption;
        std::string security   = profile.security;
        std::string sni        = profile.sni.empty() ? host : profile.sni;
        std::string fp         = profile.fingerprint.empty() ? "chrome" : profile.fingerprint;

        oss << R"(
      "protocol": "vmess",
      "settings": {
        "vnext": [{
          "address": ")" << host << R"(",
          "port": )" << portStr << R"(,
          "users": [{
            "id": ")" << uuid << R"(",
            "security": ")" << encryption << R"(",
            "alterId": 0
          }]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": ")" << (security.empty() ? "none" : security) << R"(")"
;
        if (security == "tls") {
            oss << R"(,
        "tlsSettings": {
          "serverName": ")" << sni << R"(",
          "fingerprint": ")" << fp << R"(",
          "allowInsecure": false
        })";
        }
        oss << R"(
      },
      "mux": { "enabled": true, "concurrency": 8 })";
    } else if (profile.type == "Shadowsocks") {
        std::regex addrRegex(R"(([^:]+):(\d+))");
        std::smatch match;
        std::string host    = "example.com";
        std::string portStr = "8388";
        if (std::regex_match(profile.address, match, addrRegex)) {
            host    = match[1].str();
            portStr = match[2].str();
        }
        oss << R"(
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{
          "address": ")" << host << R"(",
          "port": )" << portStr << R"(,
          "method": ")" << (profile.method.empty() ? "aes-256-gcm" : profile.method) << R"(",
          "password": ")" << profile.password << R"("
        }]
      })";
    } else {
        oss << R"(
      "protocol": "freedom")";
    }
}

// ── TUN-mode config (xray tun inbound) ────────────────────────────────────
// xray creates the virtual network interface itself.
// NOTE: xray tun does NOT support autoRoute/strictRoute (those are sing-box
// fields). Routing must be set up by the host OS after xray starts —
// see setupTunRoutes() below.
// ── Pick a TUN interface name suitable for the current OS ─────────────────
// macOS: xray requires the format "utunN" (a number suffix), e.g. utun5.
//        We auto-detect the highest existing utunN and use N+1.
// Linux: any name works; "tun0" is conventional but we fall back to "vl2tun"
//        if the user did not specify one.
static std::string pickTunName(const std::string& userPref) {
    if (!userPref.empty() && userPref != "auto") return userPref;

#ifdef __APPLE__
    // List existing utun interfaces and pick the next free number.
    int maxN = -1;
    FILE* p = popen("ifconfig 2>/dev/null | grep -oE '^utun[0-9]+' | sed 's/utun//'", "r");
    if (p) {
        char buf[16] = {0};
        while (fgets(buf, sizeof(buf), p)) {
            buf[strcspn(buf, "\n ")] = '\0';
            if (buf[0]) {
                int n = atoi(buf);
                if (n > maxN) maxN = n;
            }
        }
        pclose(p);
    }
    return "utun" + std::to_string(maxN + 1);
#else
    return "tun0";
#endif
}

std::string generateTunConfig(const Profile& profile, const Settings& settings) {
    std::ostringstream oss;

    std::string tunAddr  = settings.tunnelSubnet.empty() ? "10.8.0.1/30" : settings.tunnelSubnet;
    std::string tunName  = (settings.tunInterface.empty() || settings.tunInterface == "auto")
                           ? "vl2-xray-tun" : settings.tunInterface;

    // DNS servers JSON array
    std::string dnsBlock;
    {
        std::istringstream dss(settings.dnsServers.empty() ? "8.8.8.8,1.1.1.1" : settings.dnsServers);
        std::string srv;
        bool first = true;
        while (std::getline(dss, srv, ',')) {
            if (srv.empty()) continue;
            if (!first) dnsBlock += ", ";
            dnsBlock += "\"" + srv + "\"";
            first = false;
        }
    }

    oss << "{\n"
        << "  \"log\": {\n"
        << "    \"loglevel\": \"" << [&]() -> std::string {
               switch (settings.logLevel) {
                   case 1: return "debug";
                   case 2: return "info";
                   case 3: return "warning";
                   case 4: return "error";
                   case 5: return "none";
                   default: return "debug";
               }
           }() << "\",\n"
        << "    \"access\": \"xray-access.log\",\n"
        << "    \"error\": \"xray-tun.log\"\n"
        << "  },\n"
        << "  \"dns\": { \"servers\": [" << dnsBlock << "] },\n"
        << "  \"inbounds\": [\n"
        << "    {\n"
        << "      \"tag\": \"tun-in\",\n"
        << "      \"protocol\": \"tun\",\n"
        << "      \"settings\": {\n"
        << "        \"address\": \"" << tunAddr << "\",\n"
        << "        \"name\": \"" << tunName << "\",\n"
        << "        \"mtu\": 1450,\n"
        << "        \"autoRoute\": true,\n"
        << "        \"strictRoute\": " << (settings.killSwitch ? "true" : "false") << ",\n"
        << "        \"endpointIndependentNat\": true\n"
        << "      },\n"
        << "      \"sniffing\": {\n"
        << "        \"enabled\": true,\n"
        << "        \"destOverride\": [\"http\", \"tls\"]\n"
        << "      }\n"
        << "    }";

    // Optionally add an extra SOCKS inbound alongside the TUN so the user
    // can still use it as a regular proxy from specific apps.
    if (settings.proxyPort > 0) {
        oss << ",\n"
            << "    {\n"
            << "      \"tag\": \"socks-in\",\n"
            << "      \"port\": " << settings.proxyPort << ",\n"
            << "      \"listen\": \"127.0.0.1\",\n"
            << "      \"protocol\": \"socks\",\n"
            << "      \"settings\": { \"auth\": \"noauth\" },\n"
            << "      \"sniffing\": { \"enabled\": true, \"destOverride\": [\"http\", \"tls\"] }\n"
            << "    }";
    }
    if (settings.httpProxyPort > 0) {
        oss << ",\n"
            << "    {\n"
            << "      \"tag\": \"http-in\",\n"
            << "      \"port\": " << settings.httpProxyPort << ",\n"
            << "      \"listen\": \"127.0.0.1\",\n"
            << "      \"protocol\": \"http\",\n"
            << "      \"settings\": { \"timeout\": 360 },\n"
            << "      \"sniffing\": { \"enabled\": true, \"destOverride\": [\"http\", \"tls\"] }\n"
            << "    }";
    }

    oss << "\n  ],\n"
        << "  \"outbounds\": [\n"
        << "    {\n"
        << "      \"tag\": \"proxy\"," ;
    appendOutbound(oss, profile);
    oss << "\n"
        << "    },\n"
        << "    {\n"
        << "      \"tag\": \"direct\",\n"
        << "      \"protocol\": \"freedom\",\n"
        << "      \"settings\": {}\n"
        << "    },\n"
        << "    {\n"
        << "      \"tag\": \"block\",\n"
        << "      \"protocol\": \"blackhole\",\n"
        << "      \"settings\": {}\n"
        << "    }\n"
        << "  ],\n"
        << "  \"routing\": {\n"
        << "    \"domainStrategy\": \"IPIfNonMatch\",\n"
        << "    \"rules\": [\n"
        // Block broadcast addresses to prevent UDP socket flood
        << "      {\n"
        << "        \"type\": \"field\",\n"
        << "        \"ip\": [\"255.255.255.255/32\", \"169.254.255.255/32\"],\n"
        << "        \"outboundTag\": \"block\"\n"
        << "      },\n"
        // Direct: LAN/private addresses (do not tunnel local traffic)
        << "      {\n"
        << "        \"type\": \"field\",\n"
        << "        \"ip\": [\"geoip:private\"],\n"
        << "        \"outboundTag\": \"direct\"\n"
        << "      },\n";
    // Direct: DNS servers — prevents DNS routing loop in TUN mode.
    // Without this, getaddrinfow() queries for the proxy hostname go through
    // TUN → proxy outbound → which also calls getaddrinfow() → infinite loop.
    {
        std::istringstream dss2(settings.dnsServers.empty() ? "8.8.8.8,8.8.4.4" : settings.dnsServers);
        std::string srv2;
        std::string dnsIpJson;
        bool firstDns = true;
        while (std::getline(dss2, srv2, ',')) {
            srv2.erase(0, srv2.find_first_not_of(" \t"));
            srv2.erase(srv2.find_last_not_of(" \t") + 1);
            if (srv2.empty()) continue;
            if (!firstDns) dnsIpJson += ", ";
            dnsIpJson += "\"" + srv2 + "/32\"";
            firstDns = false;
        }
        if (!dnsIpJson.empty()) {
            oss << "      {\n"
                << "        \"type\": \"field\",\n"
                << "        \"ip\": [" << dnsIpJson << "],\n"
                << "        \"outboundTag\": \"direct\"\n"
                << "      },\n";
        }
    }
    // Direct: proxy server domain — prevents proxy TCP connection routing loop.
    // Without this, the VLESS outbound's TCP connection to the proxy server goes
    // through TUN (TLS SNI is sniffed), gets routed back to proxy → loop.
    {
        std::regex proxyHostRegex(R"(^([^:]+):\d+$)");
        std::smatch proxyHostMatch;
        if (std::regex_match(profile.address, proxyHostMatch, proxyHostRegex)) {
            std::string proxyHost = proxyHostMatch[1].str();
            if (!proxyHost.empty()) {
                oss << "      {\n"
                    << "        \"type\": \"field\",\n"
                    << "        \"domain\": [\"" << proxyHost << "\"],\n"
                    << "        \"outboundTag\": \"direct\"\n"
                    << "      },\n";
            }
        }
    }
    if (!settings.splitTunnel) {
        // Route all traffic from the TUN interface through the proxy
        oss << "      {\n"
            << "        \"type\": \"field\",\n"
            << "        \"inboundTag\": [\"tun-in\"],\n"
            << "        \"outboundTag\": \"proxy\"\n"
            << "      }\n";
    } else {
        // Split-tunnel: only route non-CN/private traffic through proxy
        oss << "      {\n"
            << "        \"type\": \"field\",\n"
            << "        \"ip\": [\"geoip:cn\"],\n"
            << "        \"outboundTag\": \"direct\"\n"
            << "      },\n"
            << "      {\n"
            << "        \"type\": \"field\",\n"
            << "        \"inboundTag\": [\"tun-in\"],\n"
            << "        \"outboundTag\": \"proxy\"\n"
            << "      }\n";
    }
    oss << "    ]\n"
        << "  }\n"
        << "}\n";
    return oss.str();
}

static bool isExecutableFile(const fs::path& path) {
    std::error_code ec;
    return fs::exists(path, ec) && !ec && fs::is_regular_file(path, ec) && !ec;
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
    if (!embedded.empty()) {
        std::error_code ec;
        if (fs::exists(embedded, ec) && !ec) return embedded;
    }

    // ── 2. Fall back to filesystem search ─────────────────────────────────
    std::vector<std::string> candidates = {"xray-core", "xray", "xray-core.exe", "xray.exe"};
    for (const auto& path : buildSearchPaths(settings)) {
        std::error_code ec;
        if (fs::is_directory(path, ec) && !ec) {
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

bool launchXrayCore(const Settings& settings, const Profile& profile, bool tunnelMode, const std::string& proxyProtocol, std::string& outLogFile, std::string& outListenAddress, ProcessId& outPid, int instanceId) {
    if (!g_headlessMode) {
        clearScreen();
        std::string instanceLabel = (instanceId == 2)
            ? tr(settings.language, "Launch xray-core #2", "Запуск xray-core #2")
            : tr(settings.language, "Launch xray-core", "Запуск xray-core");
        std::cout << "=== " << instanceLabel << " ===\n\n";
    }

    std::string binaryPath = findXrayCoreBinary(settings);
    if (binaryPath.empty()) {
        std::cerr << tr(settings.language,
            "xray-core binary not found. Put xray binary into the xray/ folder and try again.",
            "Бинарник xray-core не найден. Поместите бинарник xray в папку xray/ и попробуйте снова.") << "\n";
        if (!g_headlessMode)
            pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }

    if (!g_headlessMode)
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
    if (!available && !g_headlessMode) {
        std::cout << tr(settings.language,
            "Warning: binary version check failed. Make sure it is executable.",
            "Предупреждение: проверка версии бинарника не прошла. Убедитесь, что он исполняемый.") << "\n";
#if defined(__unix__) || defined(__APPLE__)
        std::cout << "  chmod +x \"" << binaryPath << "\"\n";
#endif
    }

    // ── Choose port, config file name, and log file name based on instance ──
    int port;
    if (instanceId == 2) {
        port = settings.proxy2Port > 0 ? settings.proxy2Port : 1081;
    } else {
        port = settings.proxyPort > 0 ? settings.proxyPort : 1080;
    }
    std::string configFileName = (instanceId == 2) ? "config2.json" : "config.json";
    std::string logFileName    = (instanceId == 2) ? "xray-core2.log" : "xray-core.log";

    std::string actualProxyProtocol = tunnelMode ? "dokodemo-door" : proxyProtocol;
    std::string config = generateConfig(profile, tunnelMode, actualProxyProtocol, port,
                                        settings.socks5Auth, settings.socks5Username, settings.socks5Password);

    std::ofstream configFile(configFileName);
    if (!configFile) {
        std::cerr << tr(settings.language,
            "Failed to create config file: ", "Не удалось создать файл конфигурации: ")
            << configFileName << "\n";
        if (!g_headlessMode)
            pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    configFile << config;
    configFile.close();

    outLogFile = logFileName;
    if (!g_headlessMode)
        std::cout << tr(settings.language, "Starting xray-core...", "Запуск xray-core...") << "\n";

#ifdef _WIN32
    // Use PowerShell Start-Process to reliably capture the PID.
    std::string pidFile = "xray" + std::to_string(instanceId) + ".pid";
    std::string launchCommand =
        "powershell -NonInteractive -Command \""
        "$p = Start-Process -FilePath '" + binaryPath + "' "
        "-ArgumentList '-config " + configFileName + "' "
        "-RedirectStandardOutput '" + outLogFile + "' "
        "-WindowStyle Hidden -PassThru; "
        "$p.Id | Set-Content -Path '" + pidFile + "'\"";
    int launchResult = std::system(launchCommand.c_str());
    Sleep(800);
    outPid = 0;
    {
        std::ifstream pidIn(pidFile);
        if (pidIn) { pidIn >> outPid; }
        DeleteFileA(pidFile.c_str());
    }
    if (outPid <= 0 && launchResult == 0) {
        // Fallback: scan tasklist and skip any known PID we already track.
        // (Works when only one extra xray.exe is present.)
        FILE* pipe = _popen("tasklist /FI \"IMAGENAME eq xray.exe\" /FO CSV /NH 2>nul", "r");
        if (!pipe) pipe = _popen("tasklist /FI \"IMAGENAME eq xray-core.exe\" /FO CSV /NH 2>nul", "r");
        if (pipe) {
            char buf[256] = {0};
            if (fgets(buf, sizeof(buf), pipe)) {
                char* pidStart = strchr(buf, ',');
                if (pidStart) {
                    pidStart++;
                    if (*pidStart == '"') pidStart++;
                    outPid = strtol(pidStart, nullptr, 10);
                }
            }
            _pclose(pipe);
        }
    }
#else
    std::string launchCommand = "nohup \"" + binaryPath + "\" -config " + configFileName + " >" + outLogFile + " 2>&1 & echo $!";
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

    if (launchResult != 0 || outPid <= 0) {
        std::cerr << tr(settings.language,
            "Failed to start xray-core. See log for details: ",
            "Не удалось запустить xray-core. Смотрите лог: ") << outLogFile << "\n";
        if (!g_headlessMode)
            pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }

    std::string listenAddress = "127.0.0.1:" + std::to_string(port);
    if (!g_headlessMode) {
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
        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
    }
    outListenAddress = listenAddress;
    return true;
}

// ── TUN-mode launcher ──────────────────────────────────────────────────────
// Generates a TUN inbound config (xray v5+), writes it, and launches xray
// with root/sudo so it can create the virtual network interface.
// outIfaceName is populated with the interface name (e.g. "tun0", "utun5").
// ── Extract server host from profile address (host:port) ──────────────────
static std::string profileServerHost(const Profile& profile) {
    size_t colon = profile.address.rfind(':');
    if (colon != std::string::npos) return profile.address.substr(0, colon);
    return profile.address;
}

// ── Resolve hostname to IP (needed for route add which requires IP) ────────
static std::string resolveHostname(const std::string& host) {
    // If already an IP, return as-is
    bool isIp = true;
    for (char c : host) {
        if (!isdigit(c) && c != '.') { isIp = false; break; }
    }
    if (isIp && host.find('.') != std::string::npos) return host;

#if defined(__unix__) || defined(__APPLE__)
    // Try dig first, then host, then nslookup
    std::string cmd = "dig +short " + host + " A 2>/dev/null | grep -E '^[0-9]+\\.' | head -1";
    FILE* p = popen(cmd.c_str(), "r");
    char buf[64] = {0};
    if (p) {
        fgets(buf, sizeof(buf), p);
        pclose(p);
        buf[strcspn(buf, "\n ")] = '\0';
        if (buf[0]) return buf;
    }

    // Fallback: getent hosts (Linux) / host command (macOS)
    memset(buf, 0, sizeof(buf));
    cmd = "host " + host + " 2>/dev/null | awk '/has address/{print $NF; exit}'";
    p = popen(cmd.c_str(), "r");
    if (p) {
        fgets(buf, sizeof(buf), p);
        pclose(p);
        buf[strcspn(buf, "\n ")] = '\0';
        if (buf[0]) return buf;
    }
#endif

    return {};  // resolution failed
}

// ── Check if we have internet connectivity through the tunnel ──────────────
static bool testConnectivity() {
#ifdef _WIN32
    return system("ping -n 1 -w 3000 8.8.8.8 >nul 2>&1") == 0;
#elif defined(__APPLE__)
    return system("ping -c 1 -t 3 8.8.8.8 >/dev/null 2>&1") == 0;
#else
    return system("ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1") == 0;
#endif
}

// ── Set up OS routing rules so traffic goes through the TUN interface ──────
// Returns true if routes applied AND connectivity confirmed.
// On failure, rolls back routes automatically.
static bool setupTunRoutes(const std::string& ifaceName,
                           const std::string& vpnServerHost,
                           const Settings& settings) {
#if defined(__APPLE__) || defined(__linux__)
    // ── 1. Resolve VPN server hostname to IP ─────────────────────────────
    std::string vpnIp;
    if (!vpnServerHost.empty() && vpnServerHost != "invalid") {
        std::cout << "  Resolving " << vpnServerHost << "... ";
        std::cout.flush();
        vpnIp = resolveHostname(vpnServerHost);
        std::cout << (vpnIp.empty() ? "failed" : vpnIp) << "\n";
    }
#endif

#ifdef __APPLE__
    // ── 2. Read current default gateway & real interface ──────────────────
    char gwBuf[64] = {0};
    char ifBuf[32] = {0};
    {
        FILE* p = popen("route -n get default 2>/dev/null | awk '/gateway/{print $2}'", "r");
        if (p) { fgets(gwBuf, sizeof(gwBuf), p); pclose(p); }
        gwBuf[strcspn(gwBuf, "\n ")] = '\0';
    }
    {
        FILE* p = popen("route -n get default 2>/dev/null | awk '/interface/{print $2}'", "r");
        if (p) { fgets(ifBuf, sizeof(ifBuf), p); pclose(p); }
        ifBuf[strcspn(ifBuf, "\n ")] = '\0';
    }

    if (!gwBuf[0]) {
        std::cout << "  ERROR: cannot detect default gateway — aborting route setup\n";
        return false;
    }
    std::cout << "  gateway=" << gwBuf << "  dev=" << ifBuf << "\n";

    // Persist state for cleanup
    { std::ofstream f("/tmp/vl2_tun_gw");     f << gwBuf; }
    { std::ofstream f("/tmp/vl2_tun_if");     f << ifBuf; }
    { std::ofstream f("/tmp/vl2_tun_server"); f << vpnIp;  }

    // ── 3. Bypass route: VPN server → real interface (MUST be IP) ─────────
    if (!vpnIp.empty()) {
        std::string cmd = "sudo route add " + vpnIp + " " + std::string(gwBuf) + " 2>/dev/null";
        system(cmd.c_str());
    } else {
        std::cout << "  WARNING: VPN server IP unknown — traffic may loop!\n";
    }

    // ── 4. Redirect all other traffic through TUN (two /1 cover all of /0) ─
    system(("sudo route add 0.0.0.0/1   -interface " + ifaceName + " 2>/dev/null").c_str());
    system(("sudo route add 128.0.0.0/1 -interface " + ifaceName + " 2>/dev/null").c_str());
    if (settings.enableIPv6) {
        system(("sudo route add -inet6 ::/1     -interface " + ifaceName + " 2>/dev/null").c_str());
        system(("sudo route add -inet6 8000::/1 -interface " + ifaceName + " 2>/dev/null").c_str());
    }

    // ── 5. Set DNS ─────────────────────────────────────────────────────────
    {
        std::string dnsArgs;
        std::istringstream d(settings.dnsServers.empty() ? "8.8.8.8,1.1.1.1" : settings.dnsServers);
        std::string s;
        while (std::getline(d, s, ',')) {
            if (!s.empty()) dnsArgs += " " + s;
        }
        FILE* svcp = popen("networksetup -listallnetworkservices 2>/dev/null | tail -n +2", "r");
        if (svcp) {
            char svcBuf[128] = {0};
            while (fgets(svcBuf, sizeof(svcBuf), svcp)) {
                svcBuf[strcspn(svcBuf, "\n")] = '\0';
                if (svcBuf[0] == '*' || svcBuf[0] == '\0') continue;
                system(("sudo networksetup -setdnsservers '" + std::string(svcBuf) + "'" + dnsArgs + " 2>/dev/null").c_str());
            }
            pclose(svcp);
        }
    }

    // ── 6. Connectivity test — rollback if broken ──────────────────────────
    std::cout << "  Testing connectivity... ";
    std::cout.flush();
    usleep(1500000);  // give routes 1.5s to settle
    if (!testConnectivity()) {
        std::cout << "FAIL — rolling back routes!\n";
        // Rollback
        system(("sudo route delete 0.0.0.0/1   -interface " + ifaceName + " 2>/dev/null").c_str());
        system(("sudo route delete 128.0.0.0/1 -interface " + ifaceName + " 2>/dev/null").c_str());
        if (!vpnIp.empty())
            system(("sudo route delete " + vpnIp + " 2>/dev/null").c_str());
        // Restore DNS
        FILE* svcp = popen("networksetup -listallnetworkservices 2>/dev/null | tail -n +2", "r");
        if (svcp) {
            char svcBuf[128] = {0};
            while (fgets(svcBuf, sizeof(svcBuf), svcp)) {
                svcBuf[strcspn(svcBuf, "\n")] = '\0';
                if (svcBuf[0] == '*' || svcBuf[0] == '\0') continue;
                system(("sudo networksetup -setdnsservers '" + std::string(svcBuf) + "' Empty 2>/dev/null").c_str());
            }
            pclose(svcp);
        }
        system("rm -f /tmp/vl2_tun_gw /tmp/vl2_tun_if /tmp/vl2_tun_server");
        return false;
    }
    std::cout << "OK\n";
    return true;

#elif defined(__linux__)
    char gwBuf[64] = {0};
    char ifBuf[32] = {0};
    {
        FILE* p = popen("ip route show default 2>/dev/null | awk 'NR==1{print $3}'", "r");
        if (p) { fgets(gwBuf, sizeof(gwBuf), p); pclose(p); }
        gwBuf[strcspn(gwBuf, "\n ")] = '\0';
    }
    {
        FILE* p = popen("ip route show default 2>/dev/null | awk 'NR==1{print $5}'", "r");
        if (p) { fgets(ifBuf, sizeof(ifBuf), p); pclose(p); }
        ifBuf[strcspn(ifBuf, "\n ")] = '\0';
    }

    if (!gwBuf[0]) {
        std::cout << "  ERROR: cannot detect default gateway — aborting\n";
        return false;
    }
    std::cout << "  gateway=" << gwBuf << "  dev=" << ifBuf << "\n";

    { std::ofstream f("/tmp/vl2_tun_gw");     f << gwBuf; }
    { std::ofstream f("/tmp/vl2_tun_if");     f << ifBuf; }
    { std::ofstream f("/tmp/vl2_tun_server"); f << vpnIp;  }

    if (!vpnIp.empty()) {
        system(("sudo ip route add " + vpnIp + " via " + std::string(gwBuf)
                + " dev " + std::string(ifBuf) + " 2>/dev/null").c_str());
    }

    system(("sudo ip route add 0.0.0.0/1   dev " + ifaceName + " 2>/dev/null").c_str());
    system(("sudo ip route add 128.0.0.0/1 dev " + ifaceName + " 2>/dev/null").c_str());

    // ── DNS: prefer systemd-resolved (Arch Linux), fallback to /etc/resolv.conf ──
    // Detect whether resolvectl is available (systemd-resolved).
    bool useResolvectl = (system("command -v resolvectl >/dev/null 2>&1") == 0);
    { std::ofstream f("/tmp/vl2_tun_use_resolvectl"); f << (useResolvectl ? "1" : "0"); }

    if (useResolvectl) {
        // Apply DNS via resolvectl — works on Arch, Ubuntu 20+, etc.
        std::istringstream d(settings.dnsServers.empty() ? "8.8.8.8,1.1.1.1" : settings.dnsServers);
        std::string s;
        std::string dnsArgs;
        while (std::getline(d, s, ',')) {
            if (!s.empty()) dnsArgs += " " + s;
        }
        system(("sudo resolvectl dns " + ifaceName + dnsArgs + " 2>/dev/null").c_str());
        system(("sudo resolvectl domain " + ifaceName + " ~. 2>/dev/null").c_str());
        // Tell systemd-resolved this link is the default DNS for all domains
        system(("sudo resolvectl default-route " + ifaceName + " yes 2>/dev/null").c_str());
    } else {
        // Fallback: edit /etc/resolv.conf directly
        system("sudo cp /etc/resolv.conf /tmp/vl2_resolv_backup 2>/dev/null");
        {
            std::ofstream rc("/tmp/vl2_resolv_new");
            std::istringstream d(settings.dnsServers.empty() ? "8.8.8.8,1.1.1.1" : settings.dnsServers);
            std::string s;
            while (std::getline(d, s, ',')) {
                if (!s.empty()) rc << "nameserver " << s << "\n";
            }
        }
        system("sudo cp /tmp/vl2_resolv_new /etc/resolv.conf 2>/dev/null");
    }

    std::cout << "  Testing connectivity... ";
    std::cout.flush();
    usleep(1500000);
    if (!testConnectivity()) {
        std::cout << "FAIL — rolling back routes!\n";
        system(("sudo ip route del 0.0.0.0/1   dev " + ifaceName + " 2>/dev/null").c_str());
        system(("sudo ip route del 128.0.0.0/1 dev " + ifaceName + " 2>/dev/null").c_str());
        if (!vpnIp.empty())
            system(("sudo ip route del " + vpnIp + " 2>/dev/null").c_str());
        if (useResolvectl) {
            system(("sudo resolvectl revert " + ifaceName + " 2>/dev/null").c_str());
        } else {
            system("sudo cp /tmp/vl2_resolv_backup /etc/resolv.conf 2>/dev/null");
        }
        system("rm -f /tmp/vl2_tun_gw /tmp/vl2_tun_if /tmp/vl2_tun_server /tmp/vl2_tun_use_resolvectl");
        return false;
    }
    std::cout << "OK\n";
    return true;
#elif defined(_WIN32)
    // ── Windows: PowerShell Add-NetRoute ─────────────────────────────────────
    // Interface name is always "vL2" (set in the xray config).
    const std::string iface = "vL2";

    // 1. Resolve VPN server hostname → IP (route add needs IP)
    std::string vpnIp;
    if (!vpnServerHost.empty() && vpnServerHost != "invalid") {
        std::cout << "  Resolving " << vpnServerHost << "... ";
        std::cout.flush();
        // nslookup outputs "Address: x.x.x.x" for the answer
        std::string nsCmd = "nslookup " + vpnServerHost + " 8.8.8.8 2>nul";
        FILE* nsp = _popen(nsCmd.c_str(), "r");
        if (nsp) {
            char buf[256] = {0};
            bool skip = true;   // skip the server/address lines for 8.8.8.8 itself
            while (fgets(buf, sizeof(buf), nsp)) {
                std::string line(buf);
                if (line.find("Name:") != std::string::npos) { skip = false; continue; }
                if (!skip && line.find("Address:") != std::string::npos) {
                    size_t p = line.find(':');
                    if (p != std::string::npos) {
                        vpnIp = line.substr(p + 2);
                        vpnIp.erase(vpnIp.find_last_not_of(" \t\r\n") + 1);
                    }
                    break;
                }
            }
            _pclose(nsp);
        }
        std::cout << (vpnIp.empty() ? "failed" : vpnIp) << "\n";
    }

    // 2. Get current default gateway and interface
    char gwBuf[64] = {0};
    char ifIdxBuf[16] = {0};
    {
        FILE* p = _popen("powershell -Command \"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop\" 2>nul", "r");
        if (p) { fgets(gwBuf, sizeof(gwBuf), p); _pclose(p); }
        gwBuf[strcspn(gwBuf, "\r\n")] = '\0';
    }
    {
        FILE* p = _popen("powershell -Command \"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).ifIndex\" 2>nul", "r");
        if (p) { fgets(ifIdxBuf, sizeof(ifIdxBuf), p); _pclose(p); }
        ifIdxBuf[strcspn(ifIdxBuf, "\r\n")] = '\0';
    }

    if (!gwBuf[0]) {
        std::cout << "  ERROR: cannot detect default gateway\n";
        return false;
    }
    std::cout << "  gateway=" << gwBuf << "  ifIndex=" << ifIdxBuf << "\n";

    // Persist for cleanup
    { std::ofstream f("C:\\vl2_tun_gw.txt");     f << gwBuf; }
    { std::ofstream f("C:\\vl2_tun_ifidx.txt");  f << ifIdxBuf; }
    { std::ofstream f("C:\\vl2_tun_server.txt"); f << vpnIp; }

    // 3. Bypass route: VPN server → real gateway (must add BEFORE default route changes)
    if (!vpnIp.empty() && gwBuf[0]) {
        std::string cmd = "route add " + vpnIp + " " + std::string(gwBuf) + " metric 1 >nul 2>&1";
        system(cmd.c_str());
    } else {
        std::cout << "  WARNING: VPN server IP unknown — may loop!\n";
    }

    // 4. Wait for vL2 interface to appear
    std::cout << "  Waiting for vL2 interface... ";
    std::cout.flush();
    bool ifaceFound = false;
    for (int i = 0; i < 8; ++i) {
        Sleep(500);
        FILE* chk = _popen("powershell -Command \"if (Get-NetAdapter -Name 'vL2' -ErrorAction SilentlyContinue) { 'found' }\" 2>nul", "r");
        if (chk) {
            char cb[16] = {0};
            fgets(cb, sizeof(cb), chk);
            _pclose(chk);
            if (strstr(cb, "found")) { ifaceFound = true; break; }
        }
    }
    std::cout << (ifaceFound ? "OK\n" : "not found (continuing anyway)\n");

    // 5. Set interface description to "vL2 tun" via PowerShell
    system("powershell -Command \"try { Set-NetAdapter -Name 'vL2' -Description 'vL2 tun' -Confirm:$false -ErrorAction Stop } catch {}\" >nul 2>&1");

    // 6. Route all traffic through vL2 (two /1 cover all of /0)
    system("powershell -Command \"Remove-NetRoute -DestinationPrefix '0.0.0.0/1'   -Confirm:$false -ErrorAction SilentlyContinue\" >nul 2>&1");
    system("powershell -Command \"Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -Confirm:$false -ErrorAction SilentlyContinue\" >nul 2>&1");
    system("powershell -Command \"New-NetRoute -DestinationPrefix '0.0.0.0/1'   -InterfaceAlias 'vL2' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore\" >nul 2>&1");
    system("powershell -Command \"New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'vL2' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore\" >nul 2>&1");

    // 7. Set DNS on vL2 interface
    {
        std::string dnsArgs;
        std::istringstream d(settings.dnsServers.empty() ? "8.8.8.8,1.1.1.1" : settings.dnsServers);
        std::string s;
        bool first = true;
        while (std::getline(d, s, ',')) {
            if (s.empty()) continue;
            if (first) {
                system(("netsh interface ip set dns name=\"vL2\" static " + s + " primary >nul 2>&1").c_str());
                first = false;
            } else {
                system(("netsh interface ip add dns name=\"vL2\" " + s + " index=2 >nul 2>&1").c_str());
            }
        }
        // Also set DNS on all other adapters to avoid leaks
        system(("powershell -Command \"Get-NetAdapter | Where-Object {$_.Name -ne 'vL2' -and $_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses '" + (settings.dnsServers.empty() ? "8.8.8.8" : settings.dnsServers.substr(0, settings.dnsServers.find(','))) + "' }\" >nul 2>&1").c_str());
    }

    // 8. Flush DNS cache
    system("ipconfig /flushdns >nul 2>&1");

    // 9. Connectivity test
    std::cout << "  Testing connectivity... ";
    std::cout.flush();
    Sleep(2000);
    if (!testConnectivity()) {
        std::cout << "FAIL — rolling back!\n";
        system("powershell -Command \"Remove-NetRoute -DestinationPrefix '0.0.0.0/1'   -Confirm:$false -ErrorAction SilentlyContinue\" >nul 2>&1");
        system("powershell -Command \"Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -Confirm:$false -ErrorAction SilentlyContinue\" >nul 2>&1");
        if (!vpnIp.empty()) {
            system(("route delete " + vpnIp + " >nul 2>&1").c_str());
        }
        system("powershell -Command \"Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ResetServerAddresses }\" >nul 2>&1");
        system("ipconfig /flushdns >nul 2>&1");
        system("del /f C:\\vl2_tun_gw.txt C:\\vl2_tun_ifidx.txt C:\\vl2_tun_server.txt >nul 2>&1");
        return false;
    }
    std::cout << "OK\n";
    return true;

#else
    (void)ifaceName; (void)vpnServerHost; (void)settings;
    return false;
#endif
}

// ── Restore routes and DNS set by setupTunRoutes() ─────────────────────────
static void cleanupTunRoutes(const std::string& ifaceName) {
#ifdef __APPLE__
    // Restore VPN server specific route
    std::string vpnServer;
    { std::ifstream f("/tmp/vl2_tun_server"); f >> vpnServer; }
    if (!vpnServer.empty()) {
        system(("sudo route delete " + vpnServer + " 2>/dev/null").c_str());
    }

    // Remove the two /1 routes
    system(("sudo route delete 0.0.0.0/1   -interface " + ifaceName + " 2>/dev/null").c_str());
    system(("sudo route delete 128.0.0.0/1 -interface " + ifaceName + " 2>/dev/null").c_str());
    system("sudo route delete -inet6 ::/1     2>/dev/null");
    system("sudo route delete -inet6 8000::/1 2>/dev/null");

    // Restore DNS — set all services back to "Empty" (DHCP-assigned)
    FILE* svcp = popen("networksetup -listallnetworkservices 2>/dev/null | tail -n +2", "r");
    if (svcp) {
        char svcBuf[128] = {0};
        while (fgets(svcBuf, sizeof(svcBuf), svcp)) {
            svcBuf[strcspn(svcBuf, "\n")] = '\0';
            if (svcBuf[0] == '*') continue;
            system(("sudo networksetup -setdnsservers '" + std::string(svcBuf) + "' Empty 2>/dev/null").c_str());
        }
        pclose(svcp);
    }
    system("rm -f /tmp/vl2_tun_gw /tmp/vl2_tun_if /tmp/vl2_tun_server /tmp/vl2_tun_dns_backup");

#elif defined(__linux__)
    std::string vpnServer;
    { std::ifstream f("/tmp/vl2_tun_server"); f >> vpnServer; }

    system(("sudo ip route del 0.0.0.0/1 dev " + ifaceName + " 2>/dev/null").c_str());
    system(("sudo ip route del 128.0.0.0/1 dev " + ifaceName + " 2>/dev/null").c_str());
    if (!vpnServer.empty()) {
        system(("sudo ip route del " + vpnServer + " 2>/dev/null").c_str());
    }

    // Restore DNS: prefer resolvectl if it was used during setup
    std::string useRc;
    { std::ifstream f("/tmp/vl2_tun_use_resolvectl"); f >> useRc; }
    if (useRc == "1") {
        system(("sudo resolvectl revert " + ifaceName + " 2>/dev/null").c_str());
    } else {
        system("sudo cp /tmp/vl2_resolv_backup /etc/resolv.conf 2>/dev/null");
    }
    system("rm -f /tmp/vl2_tun_gw /tmp/vl2_tun_if /tmp/vl2_tun_server /tmp/vl2_resolv_backup /tmp/vl2_resolv_new /tmp/vl2_tun_use_resolvectl");

#elif defined(_WIN32)
    (void)ifaceName;
    std::string vpnIp;
    { std::ifstream f("C:\\vl2_tun_server.txt"); f >> vpnIp; }

    // Remove the two /1 routes
    system("powershell -Command \"Remove-NetRoute -DestinationPrefix '0.0.0.0/1'   -Confirm:$false -ErrorAction SilentlyContinue\" >nul 2>&1");
    system("powershell -Command \"Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -Confirm:$false -ErrorAction SilentlyContinue\" >nul 2>&1");
    // Remove bypass route for VPN server
    if (!vpnIp.empty()) {
        system(("route delete " + vpnIp + " >nul 2>&1").c_str());
    }
    // Restore DNS to DHCP on all adapters
    system("powershell -Command \"Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ResetServerAddresses }\" >nul 2>&1");
    system("ipconfig /flushdns >nul 2>&1");
    system("del /f C:\\vl2_tun_gw.txt C:\\vl2_tun_ifidx.txt C:\\vl2_tun_server.txt >nul 2>&1");
#endif
}

bool launchXrayTun(const Settings& settings, const Profile& profile,
                   std::string& outLogFile, std::string& outIfaceName, ProcessId& outPid) {
    clearScreen();
    Language lang = settings.language;
    std::cout << "=== " << tr(lang, "Launch TUN Tunnel", "Запуск TUN туннеля") << " ===\n\n";

    std::string binaryPath = findXrayCoreBinary(settings);
    if (binaryPath.empty()) {
        std::cout << tr(lang,
            "xray-core binary not found. Put it in the xray/ folder first.",
            "Бинарник xray-core не найден. Сначала поместите его в папку xray/.") << "\n";
        pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    std::cout << tr(lang, "Binary: ", "Бинарник: ") << binaryPath << "\n";

    // Resolve TUN interface name BEFORE generating config so we know what to wait for.
    // pickTunName() auto-detects the next free utunN on macOS, tun0 on Linux.
    // We store it into a local copy of settings so generateTunConfig uses the same name.
    Settings settingsForTun = settings;
    settingsForTun.tunInterface = pickTunName(settings.tunInterface);
    std::cout << tr(lang, "TUN interface will be: ", "Имя TUN интерфейса: ") << settingsForTun.tunInterface << "\n";

    // Generate TUN config
    std::string config = generateTunConfig(profile, settingsForTun);
    std::ofstream configFile("config_tun.json");
    if (!configFile) {
        std::cout << tr(lang, "Failed to create config_tun.json", "Не удалось создать config_tun.json") << "\n";
        pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    configFile << config;
    configFile.close();

    outLogFile = "xray-tun.log";

    // TUN interface requires elevated privileges
    std::cout << tr(lang,
        "TUN mode requires root/sudo to create the virtual network interface.\n",
        "Режим TUN требует root/sudo для создания виртуального сетевого интерфейса.\n") << "\n";

#if defined(__APPLE__) || defined(__linux__)
    // On Unix, launch with sudo so xray can create the utun/tun device.
    std::string launchCmd = "sudo \"" + binaryPath + "\" -config config_tun.json >" + outLogFile + " 2>&1 & echo $!";
    std::cout << tr(lang, "Starting (may prompt for sudo password)...",
                         "Запуск (может потребовать пароль sudo)...") << "\n";
    FILE* pipe = popen(launchCmd.c_str(), "r");
    if (!pipe) {
        std::cout << tr(lang, "Failed to start xray-core.", "Не удалось запустить xray-core.") << "\n";
        pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    char pidBuf[32] = {0};
    if (!fgets(pidBuf, sizeof(pidBuf), pipe)) {
        pclose(pipe);
        std::cout << tr(lang, "Failed to read xray-core PID.", "Не удалось прочитать PID xray-core.") << "\n";
        pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }
    pclose(pipe);
    outPid = strtol(pidBuf, nullptr, 10);
    if (outPid <= 0) {
        std::cout << tr(lang, "Invalid PID — xray may not have started.", "Неверный PID — xray мог не запуститься.") << "\n";
        pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }

    // Wait for xray to bring up the interface we expect.
    const std::string& expectedIface = settingsForTun.tunInterface;
    std::cout << tr(lang, "Waiting for TUN interface to come up...", "Ожидание поднятия TUN интерфейса...") << "\n";
    for (int i = 0; i < 8; ++i) {
        usleep(800000);  // 0.8 s per iteration
#ifdef __APPLE__
        std::string checkCmd = "ifconfig " + expectedIface + " >/dev/null 2>&1";
#else
        std::string checkCmd = "ip link show " + expectedIface + " >/dev/null 2>&1";
#endif
        if (system(checkCmd.c_str()) == 0) {
            outIfaceName = expectedIface;
            break;
        }
    }

    if (outIfaceName.empty()) {
        outIfaceName = expectedIface;  // use expected name anyway, routes may still work
        std::cout << tr(lang,
            "WARNING: interface not detected yet, continuing...",
            "ПРЕДУПРЕЖДЕНИЕ: интерфейс ещё не обнаружен, продолжаем...") << "\n";
    }

    std::cout << tr(lang, "TUN interface: ", "TUN интерфейс: ") << outIfaceName << "\n";
    std::cout << tr(lang, "Tunnel subnet: ", "Подсеть туннеля: ") << settingsForTun.tunnelSubnet << "\n";

    // ── Set up OS routing rules ────────────────────────────────────────────
    std::cout << tr(lang,
        "Setting up routing rules (hostname will be resolved to IP)...",
        "Настройка маршрутов (хостнейм будет разрешён в IP)...") << "\n";
    std::string vpnServer = profileServerHost(profile);
    bool routesOk = setupTunRoutes(outIfaceName, vpnServer, settingsForTun);
    if (!routesOk) {
        std::cout << "\n" << tr(lang,
            "Route setup failed or connectivity test failed — routes rolled back.\n"
            "xray is still running as SOCKS5 proxy on 127.0.0.1:",
            "Маршруты не применены или тест связи провалился — откат выполнен.\n"
            "xray продолжает работать как SOCKS5 прокси на 127.0.0.1:")
            << settings.proxyPort << "\n";
        std::cout << tr(lang,
            "Check xray-tun.log for errors.",
            "Проверьте xray-tun.log для диагностики.") << "\n";
        // Show last lines of log
        system(("tail -20 " + outLogFile).c_str());
    } else {
        std::cout << tr(lang, "Routes configured. Tunnel is active.", "Маршруты настроены. Туннель активен.") << "\n";
    }

    if (settings.proxyPort > 0) {
        std::cout << tr(lang, "SOCKS5 also on: ", "SOCKS5 также на: ")
                  << "127.0.0.1:" << settings.proxyPort << "\n";
    }
    if (settings.killSwitch) {
        std::cout << tr(lang,
            "[kill-switch ON] Traffic blocked if tunnel drops.",
            "[kill-switch ВКЛ] Трафик блокируется при обрыве туннеля.") << "\n";
    }

#elif defined(_WIN32)
    // On Windows, xray uses WinTUN to create the virtual adapter.
    // Must be run as Administrator; wintun.dll must be next to the xray binary.
    std::cout << tr(lang,
        "Windows TUN: ensure WinTUN (wintun.dll) is present next to the binary.\n"
        "Administrator rights are required to create the TUN interface.\n",
        "Windows TUN: убедитесь, что WinTUN (wintun.dll) находится рядом с бинарником.\n"
        "Для создания TUN интерфейса требуются права Администратора.\n");

    // Launch xray hidden; redirect output to log file.
    std::string launchCmd =
        "powershell -NonInteractive -Command \""
        "$p = Start-Process -FilePath '" + binaryPath + "' "
        "-ArgumentList '-config config_tun.json' "
        "-RedirectStandardOutput " + outLogFile + " "
        "-WindowStyle Hidden -PassThru; "
        "$p.Id | Set-Content -Path 'xray_tun.pid'\"";

    if (std::system(launchCmd.c_str()) != 0) {
        std::cout << tr(lang, "Failed to start xray-core.", "Не удалось запустить xray-core.") << "\n";
        pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return false;
    }

    // Read PID written by PowerShell
    Sleep(1200);
    outPid = 0;
    {
        std::ifstream pidIn("xray_tun.pid");
        if (pidIn) { pidIn >> outPid; }
        DeleteFileA("xray_tun.pid");
    }
    if (outPid <= 0) {
        // Fallback: find by image name
        FILE* pipe = _popen("tasklist /FI \"IMAGENAME eq xray.exe\" /FO CSV /NH 2>nul", "r");
        if (!pipe) {
            pipe = _popen("tasklist /FI \"IMAGENAME eq xray-core.exe\" /FO CSV /NH 2>nul", "r");
        }
        if (pipe) {
            char buf[256] = {0};
            if (fgets(buf, sizeof(buf), pipe)) {
                char* p = strchr(buf, ',');
                if (p) { ++p; if (*p == '"') ++p; outPid = strtol(p, nullptr, 10); }
            }
            _pclose(pipe);
        }
    }

    outIfaceName = "vl2-xray-tun";

    // Determine TUN gateway from tunnel subnet (e.g. "10.8.0.1/30" → "10.8.0.1")
    std::string gateway;
    {
        std::string sub = settings.tunnelSubnet.empty() ? "10.8.0.1/30" : settings.tunnelSubnet;
        size_t sl = sub.find('/');
        gateway = (sl != std::string::npos) ? sub.substr(0, sl) : sub;
    }

    // Detect the WinTUN adapter via "netsh interface ipv4 show interfaces".
    // This is fast (no PowerShell overhead), has no quoting/pipe issues, and works
    // regardless of what name xray assigns to the adapter on Windows.
    std::cout << tr(lang, "Waiting for TUN interface to come up...", "Ожидание поднятия TUN интерфейса...") << "\n";
    Sleep(2000);  // xray logs "vl2 up" ~400 ms after start; 2 s is plenty

    bool ifaceUp = false;
    std::string ifIdxStr;
    std::string tunAdapterName;

    auto isKnownNonTun = [](const char* line) {
        static const char* kSkipL[] = {
            "Loopback", "Teredo", "Hyper-V", "Radmin", "Realtek",
            "Wi-Fi", "Ethernet", "Bluetooth", nullptr
        };
        for (int k = 0; kSkipL[k]; ++k)
            if (strstr(line, kSkipL[k])) return true;
        return false;
    };

    for (int attempt = 0; attempt < 4 && !ifaceUp; ++attempt) {
        if (attempt > 0) Sleep(1000);
        FILE* ns = _popen("netsh interface ipv4 show interfaces 2>nul", "r");
        if (!ns) continue;
        char line[512];
        while (fgets(line, sizeof(line), ns) && !ifaceUp) {
            if (isKnownNonTun(line)) continue;
            int idx = 0;
            if (sscanf(line, " %d", &idx) != 1 || idx <= 0) continue;
            // Any non-skipped numbered interface is likely the TUN
            ifIdxStr = std::to_string(idx);
            // Extract adapter name: everything after the state keyword
            line[strcspn(line, "\r\n")] = '\0';
            const char* stateWords[] = {"connected", "disconnected", "unreachable", nullptr};
            for (int k = 0; stateWords[k] && tunAdapterName.empty(); ++k) {
                const char* p = strstr(line, stateWords[k]);
                if (p) {
                    p += strlen(stateWords[k]);
                    while (*p == ' ') ++p;
                    if (*p) tunAdapterName = p;
                }
            }
            ifaceUp = true;
        }
        _pclose(ns);
    }

    if (ifaceUp) {
        std::cout << tr(lang, "Interface index: ", "Индекс интерфейса: ") << ifIdxStr;
        if (!tunAdapterName.empty())
            std::cout << "  (\"" << tunAdapterName << "\")";
        std::cout << "\n";
        {
            auto runRoute = [&](const std::string& cmd) {
                std::cout << "  > " << cmd << "\n";
                FILE* rp = _popen((cmd + " 2>&1").c_str(), "r");
                if (rp) {
                    char rb[256] = {0};
                    while (fgets(rb, sizeof(rb), rp)) {
                        rb[strcspn(rb, "\r\n")] = '\0';
                        if (rb[0]) std::cout << "    " << rb << "\n";
                    }
                    int rc = _pclose(rp);
                    std::cout << tr(lang,
                        rc == 0 ? "    [OK]\n" : "    [FAILED]\n",
                        rc == 0 ? "    [OK]\n" : "    [ОШИБКА]\n");
                    return rc == 0;
                }
                return false;
            };

            // ── Step 1: Detect original default gateway (BEFORE TUN routes) ──────
            // We must do this now, while the original routing is still in effect.
            std::string origGateway;
            {
                FILE* rp = _popen("route print 0.0.0.0 2>nul", "r");
                if (rp) {
                    char line[256];
                    int bestMetric = 999999;
                    while (fgets(line, sizeof(line), rp)) {
                        char gw[64] = {}, iface[64] = {};
                        int metric = 0;
                        // Matches rows: "  0.0.0.0  0.0.0.0  GW  IFACE  METRIC"
                        if (sscanf(line, " 0.0.0.0 0.0.0.0 %63s %63s %d",
                                   gw, iface, &metric) == 3
                            && strcmp(gw, "On-link") != 0
                            && metric < bestMetric) {
                            bestMetric = metric;
                            origGateway = gw;
                        }
                    }
                    _pclose(rp);
                }
            }

            // ── Step 2: Resolve proxy hostname → IP (while original routing active) ─
            // After TUN routes are added, getaddrinfow() would loop back through TUN.
            std::string proxyIP;
            {
                std::string proxyHostname;
                {
                    std::regex addrR(R"(^([^:]+):\d+$)");
                    std::smatch m;
                    if (std::regex_match(profile.address, m, addrR))
                        proxyHostname = m[1].str();
                }
                if (!proxyHostname.empty()) {
                    // If it's already an IP, use it directly.
                    std::regex ipR(R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)");
                    if (std::regex_match(proxyHostname, ipR)) {
                        proxyIP = proxyHostname;
                    } else {
                        // Use ping to resolve; it prints "Pinging host [IP] with ..."
                        std::string pingCmd = "ping -n 1 -4 -w 3000 " + proxyHostname + " 2>nul";
                        FILE* pp = _popen(pingCmd.c_str(), "r");
                        if (pp) {
                            char buf[256];
                            if (fgets(buf, sizeof(buf), pp)) {
                                const char* lb = strchr(buf, '[');
                                const char* rb = lb ? strchr(lb, ']') : nullptr;
                                if (lb && rb && rb > lb + 1)
                                    proxyIP = std::string(lb + 1, rb);
                            }
                            _pclose(pp);
                        }
                    }
                }
            }

            // ── Step 3: Add /32 host routes BEFORE TUN /1 routes ─────────────────
            // /32 has longer prefix than /1, so it always wins regardless of metric.
            // This ensures proxy server and DNS server traffic bypasses TUN entirely,
            // breaking the routing loop that causes DNS resolution failures.
            std::vector<std::string> bypassIPs;
            if (!origGateway.empty()) {
                if (!proxyIP.empty()) {
                    std::cout << tr(lang, "  Proxy bypass: ", "  Обход TUN для прокси: ")
                              << proxyIP << " via " << origGateway << "\n";
                    runRoute("route add " + proxyIP + " mask 255.255.255.255 " + origGateway + " metric 1");
                    bypassIPs.push_back(proxyIP);
                } else {
                    std::cout << tr(lang,
                        "  Warning: could not resolve proxy IP — DNS loop may occur.\n",
                        "  Предупреждение: не удалось резолвить IP прокси — возможен DNS loop.\n");
                }
                // DNS servers bypass
                {
                    std::istringstream dss(settings.dnsServers.empty() ? "8.8.8.8,8.8.4.4"
                                                                        : settings.dnsServers);
                    std::string dns;
                    while (std::getline(dss, dns, ',')) {
                        dns.erase(0, dns.find_first_not_of(" \t"));
                        dns.erase(dns.find_last_not_of(" \t") + 1);
                        if (!dns.empty()) {
                            runRoute("route add " + dns + " mask 255.255.255.255 "
                                     + origGateway + " metric 1");
                            bypassIPs.push_back(dns);
                        }
                    }
                }
                // Save bypass IPs for cleanup
                std::ofstream bypassFile("vl2_bypass_routes.txt");
                for (const auto& ip : bypassIPs)
                    if (bypassFile) bypassFile << ip << "\n";
            } else {
                std::cout << tr(lang,
                    "  Warning: could not detect original gateway — routing loop may occur.\n",
                    "  Предупреждение: исходный шлюз не определён — возможен routing loop.\n");
            }

            // ── Step 4: Add TUN default routes ───────────────────────────────────
            // Two /1 routes together cover 0.0.0.0/0 and override the default gateway.
            runRoute("netsh interface ipv4 add route 0.0.0.0/1 interface=" + ifIdxStr + " metric=5 store=active");
            runRoute("netsh interface ipv4 add route 128.0.0.0/1 interface=" + ifIdxStr + " metric=5 store=active");

            // Set DNS on TUN adapter
            std::string dns1 = "8.8.8.8";
            if (!settings.dnsServers.empty()) {
                size_t comma = settings.dnsServers.find(',');
                dns1 = (comma != std::string::npos) ? settings.dnsServers.substr(0, comma)
                                                     : settings.dnsServers;
            }
            if (!tunAdapterName.empty())
                runRoute("netsh interface ip set dns \"" + tunAdapterName + "\" static " + dns1 + " primary");
            else
                runRoute("netsh interface ip set dns " + ifIdxStr + " static " + dns1 + " primary");

            // Verify routes
            std::cout << tr(lang, "Verifying routes...\n", "Проверка маршрутов...\n");
            FILE* vp = _popen("route print 0.0.0.0 2>&1", "r");
            if (vp) {
                char vb[256] = {0};
                while (fgets(vb, sizeof(vb), vp)) {
                    vb[strcspn(vb, "\r\n")] = '\0';
                    if (vb[0]) std::cout << "  " << vb << "\n";
                }
                _pclose(vp);
            }
        }
    } else {
        std::cout << tr(lang,
            "Warning: TUN interface did not come up — check that wintun.dll is present "
            "and the process has Administrator rights.",
            "Предупреждение: TUN интерфейс не поднялся — убедитесь, что wintun.dll присутствует "
            "и процесс запущен с правами Администратора.") << "\n";
    }
#else
    std::cout << tr(lang, "TUN mode is not supported on this platform.", "Режим TUN не поддерживается на этой платформе.") << "\n";
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
    return false;
#endif

    std::cout << "\n" << tr(lang, "TUN tunnel active. Log: ", "TUN туннель активен. Лог: ") << outLogFile << "\n";
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
    return true;
}

// ── Cleanup for TUN mode ───────────────────────────────────────────────────
bool cleanupTunVPN(const Settings& settings) {
    Language lang = settings.language;
    std::cout << tr(lang, "Removing TUN routing rules...",
                         "Удаление правил маршрутизации TUN...") << "\n";
#if defined(__APPLE__) || defined(__linux__)
    // Read back interface name from what was detected at launch time.
    // We pass "tun?" as fallback — cleanupTunRoutes will still try.
    std::string ifaceName;
    {
        // Try to detect current utun/tun interface
#ifdef __APPLE__
        FILE* p = popen("ifconfig 2>/dev/null | grep -E '^utun[0-9]+:' | tail -1 | cut -d: -f1", "r");
#else
        FILE* p = popen("ip link 2>/dev/null | grep -oE 'tun[0-9]+' | tail -1", "r");
#endif
        if (p) {
            char buf[32] = {0};
            if (fgets(buf, sizeof(buf), p)) {
                buf[strcspn(buf, "\n ")] = '\0';
                ifaceName = buf;
            }
            pclose(p);
        }
    }
    if (ifaceName.empty()) ifaceName = "tun0";
    cleanupTunRoutes(ifaceName);
    std::cout << tr(lang, "Routes restored.", "Маршруты восстановлены.") << "\n";
#elif defined(_WIN32)
    // Remove the split-default routes we added when the tunnel started.
    system("route delete 0.0.0.0 mask 128.0.0.0 >nul 2>&1");
    system("route delete 128.0.0.0 mask 128.0.0.0 >nul 2>&1");
    // Remove bypass host routes (proxy server + DNS servers).
    {
        std::ifstream bypassFile("vl2_bypass_routes.txt");
        std::string ip;
        while (std::getline(bypassFile, ip)) {
            ip.erase(0, ip.find_first_not_of(" \t\r\n"));
            ip.erase(ip.find_last_not_of(" \t\r\n") + 1);
            if (!ip.empty()) {
                std::string cmd = "route delete " + ip + " >nul 2>&1";
                system(cmd.c_str());
            }
        }
    }
    DeleteFileA("vl2_bypass_routes.txt");
    // Restore DNS on the TUN adapter to DHCP (adapter disappears anyway, but clean up).
    system("netsh interface ip set dns \"vl2-xray-tun\" dhcp >nul 2>&1");
    // WinTUN adapter is automatically removed when xray.exe exits.
    std::cout << tr(lang, "Windows: routes removed, WinTUN interface released.",
                         "Windows: маршруты удалены, WinTUN интерфейс освобождён.") << "\n";
#endif
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
#ifdef _WIN32
    // Try to find xray.exe or xray-core.exe via tasklist
    const char* queries[] = {
        "tasklist /FI \"IMAGENAME eq xray.exe\" /FO CSV /NH 2>nul",
        "tasklist /FI \"IMAGENAME eq xray-core.exe\" /FO CSV /NH 2>nul"
    };
    for (const char* q : queries) {
        FILE* pipe = _popen(q, "r");
        if (!pipe) continue;
        char buf[512] = {0};
        while (fgets(buf, sizeof(buf), pipe)) {
            // CSV format: "xray.exe","1234","Console","1","..."
            if (buf[0] != '"') continue;
            char imgName[128] = {0};
            long pid = 0;
            if (sscanf(buf, "\"%127[^\"]\",%ld", imgName, &pid) == 2 && pid > 0) {
                info.pid = static_cast<ProcessId>(pid);
                info.binaryPath = imgName;
                break;
            }
        }
        _pclose(pipe);
        if (info.pid > 0) break;
    }
#elif defined(__unix__) || defined(__APPLE__)
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
    std::error_code _ec;
    if (!xrayPath.empty() && std::filesystem::exists(xrayPath, _ec) && !_ec) {
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

// ── Per-app proxy helpers ──────────────────────────────────────────────────

bool isProxychainsAvailable() {
#if defined(__unix__) || defined(__APPLE__)
    return system("command -v proxychains4 >/dev/null 2>&1") == 0
        || system("command -v proxychains  >/dev/null 2>&1") == 0;
#else
    return false;
#endif
}

std::string writeProxychainsConfig(int proxyPort) {
    const std::string cfgPath = "/tmp/vl2_proxychains.conf";
    std::ofstream cfg(cfgPath);
    cfg << "strict_chain\n"
        << "proxy_dns\n"
        << "tcp_read_time_out 15000\n"
        << "tcp_connect_time_out 8000\n"
        << "[ProxyList]\n"
        << "socks5 127.0.0.1 " << proxyPort << "\n";
    return cfgPath;
}

// ── Detect Electron/Chromium-based apps ───────────────────────────────────
// These apps ignore HTTP_PROXY env-vars and require --proxy-server CLI flag.
static bool isElectronApp(const std::string& cmd) {
    static const std::vector<std::string> knownElectron = {
        "discord", "telegram", "telegram-desktop", "slack", "teams",
        "code", "vscode", "vscodium", "atom", "notion", "obsidian",
        "spotify", "skype", "viber", "element", "electron", "chromium",
        "chrome", "brave", "opera"
    };
    std::string lower = cmd;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& name : knownElectron)
        if (lower.find(name) != std::string::npos) return true;
    return false;
}

// Resolve a bare command word ("discord") to its full path ("/usr/bin/discord").
static std::string resolveBin(const std::string& word) {
    if (word.empty() || word[0] == '/' || word[0] == '.') return word;
#if defined(__unix__) || defined(__APPLE__)
    FILE* p = popen(("command -v " + word + " 2>/dev/null").c_str(), "r");
    if (!p) return word;
    char buf[512] = {0};
    fgets(buf, sizeof(buf), p);
    pclose(p);
    buf[strcspn(buf, "\n ")] = '\0';
    return buf[0] ? std::string(buf) : word;
#else
    return word;
#endif
}

void launchAppThroughProxy(const std::string& command, int proxyPort,
                           int httpProxyPort, Language lang) {
#if defined(__unix__) || defined(__APPLE__)
    clearScreen();
    std::cout << "=== " << tr(lang, "Launch app through proxy", "Запуск приложения через прокси") << " ===\n\n";
    std::cout << tr(lang, "Command: ", "Команда: ") << command << "\n";
    std::cout << tr(lang, "SOCKS5:  127.0.0.1:", "SOCKS5:  127.0.0.1:") << proxyPort << "\n\n";

    // ── Per-app log file ───────────────────────────────────────────────────
    std::string appWord = command.substr(0, command.find(' '));
    appWord = appWord.substr(appWord.rfind('/') + 1);
    std::string logFile = "/tmp/vl2_app_" + appWord + ".log";

    std::string launchCmd;
    bool electron = isElectronApp(command);

    if (electron) {
        // ── Electron / Chromium ────────────────────────────────────────────
        // Split binary and extra args
        size_t sp = command.find(' ');
        std::string binWord  = command.substr(0, sp);
        std::string restArgs = (sp != std::string::npos) ? command.substr(sp) : "";

        std::string resolvedBin = resolveBin(binWord);

        std::string proxyFlag = "--proxy-server=socks5://127.0.0.1:" + std::to_string(proxyPort);

        std::cout << tr(lang,
            "Electron app detected — injecting --proxy-server flag.\n",
            "Обнаружено Electron-приложение — добавляется --proxy-server.\n");

        launchCmd = "nohup \"" + resolvedBin + "\" " + proxyFlag + restArgs
                    + " >\"" + logFile + "\" 2>&1 &";

    } else if (isProxychainsAvailable()) {
        // ── proxychains: intercepts all TCP syscalls ───────────────────────
        std::string cfgPath = writeProxychainsConfig(proxyPort);
        bool has4 = (system("command -v proxychains4 >/dev/null 2>&1") == 0);
        std::string pchains = has4 ? "proxychains4" : "proxychains";

        std::cout << tr(lang,
            "Using proxychains — all TCP from this app goes through proxy.\n",
            "Используется proxychains — весь TCP приложения идёт через прокси.\n");

        launchCmd = "nohup " + pchains + " -f \"" + cfgPath + "\" " + command
                    + " >\"" + logFile + "\" 2>&1 &";
    } else {
        // ── Env-var fallback ───────────────────────────────────────────────
        std::string socksUrl = "socks5://127.0.0.1:" + std::to_string(proxyPort);
        std::string httpUrl  = httpProxyPort > 0
            ? ("http://127.0.0.1:" + std::to_string(httpProxyPort))
            : ("http://127.0.0.1:" + std::to_string(proxyPort));

        std::cout << tr(lang,
            "Using proxy env-vars (HTTP_PROXY / ALL_PROXY).\n"
            "  For Electron apps (Discord etc.) this may not work — they need proxychains.\n"
            "  Install: pacman -S proxychains-ng\n",
            "Используются переменные окружения прокси (HTTP_PROXY / ALL_PROXY).\n"
            "  Для Electron-приложений (Discord и т.д.) нужен proxychains.\n"
            "  Установка: pacman -S proxychains-ng\n");

        launchCmd = "nohup env"
                    " ALL_PROXY="   + socksUrl + " all_proxy="   + socksUrl +
                    " HTTP_PROXY="  + httpUrl  + " http_proxy="  + httpUrl  +
                    " HTTPS_PROXY=" + httpUrl  + " https_proxy=" + httpUrl  +
                    " " + command + " >\"" + logFile + "\" 2>&1 &";
    }

    std::cout << tr(lang, "Launching...", "Запуск...") << "\n";
    int ret = system(launchCmd.c_str());

    if (ret == 0) {
        std::cout << tr(lang, "App started in background.\n", "Приложение запущено в фоне.\n");
        std::cout << tr(lang, "Log: ", "Лог: ") << logFile << "\n";
        usleep(1200000); // wait 1.2s for app to produce initial output
        std::cout << "\n--- " << tr(lang, "last output:", "последний вывод:") << " ---\n";
        system(("tail -8 \"" + logFile + "\" 2>/dev/null || echo '(no output yet)'").c_str());
        std::cout << "---\n";
    } else {
        std::cout << tr(lang, "Launch returned error. Log:\n", "Запуск вернул ошибку. Лог:\n");
        system(("cat \"" + logFile + "\" 2>/dev/null").c_str());
    }
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
#else
    (void)command; (void)proxyPort; (void)httpProxyPort;
    clearScreen();
    std::cout << tr(lang,
        "Per-app proxy is not supported on Windows in this build.\n"
        "Use system proxy settings or a tool like Proxifier.",
        "Прокси для отдельных приложений не поддерживается в Windows в этой сборке.\n"
        "Используйте системные настройки прокси или программу Proxifier.") << "\n";
    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
#endif
}

// ═══════════════════════════════════════════════════════════════════════════
// VPN NAMESPACE MODE  (Linux only)
//
// Creates an isolated network namespace (vl2ns) where ALL TCP/UDP traffic
// from any app is forced through xray's SOCKS5 proxy via tun2socks.
// Unlike the proxy env-var approach, this works for every app — including
// those that ignore HTTP_PROXY (Discord, games, custom binaries, etc.).
//
// Architecture:
//   main netns         vl2ns
//   ──────────         ─────────────────────────────────────────
//   xray SOCKS5  ←──  veth10200.0.1  ←── tun2socks ←── vl2tun
//   0.0.0.0:1080       10.200.0.2                          ↑
//                                               all app TCP/UDP
//
// Requirements: iproute2, tun2socks, iptables
//   sudo pacman -S iproute2 tun2socks iptables
// ═══════════════════════════════════════════════════════════════════════════

static const std::string NS_NAME    = "vl2ns";
static const std::string NS_VETH_H  = "vl2h";   // host side
static const std::string NS_VETH_N  = "vl2n";   // namespace side
static const std::string NS_HOST_IP = "10.200.0.1";
static const std::string NS_NS_IP   = "10.200.0.2";
static const std::string NS_SUBNET  = "10.200.0.0/24";
static const std::string NS_TUN     = "vl2tun";

bool isNetNSModeAvailable() {
#ifdef __linux__
    return system("command -v ip        >/dev/null 2>&1") == 0 &&
           system("command -v tun2socks >/dev/null 2>&1") == 0;
#else
    return false;
#endif
}

// ── Generate xray SOCKS5 config that binds to ALL interfaces ───────────────
// Needed so xray is reachable at 10.200.0.1:<port> from inside the namespace.
std::string generateNetNSSocksConfig(const Profile& profile, const Settings& settings) {
    std::ostringstream oss;
    int port = settings.proxyPort > 0 ? settings.proxyPort : 1080;

    auto logLevelStr = [&]() -> std::string {
        switch (settings.logLevel) {
            case 1: return "debug"; case 2: return "info";
            case 3: return "warning"; case 4: return "error";
            case 5: return "none"; default: return "warning";
        }
    }();

    oss << "{\n"
        << "  \"log\": { \"loglevel\": \"" << logLevelStr << "\" },\n"
        << "  \"inbounds\": [{\n"
        << "    \"port\": " << port << ",\n"
        << "    \"listen\": \"0.0.0.0\",\n"   // ← all interfaces
        << "    \"protocol\": \"socks\",\n"
        << "    \"settings\": { \"auth\": \""
        << (settings.socks5Auth && !settings.socks5Username.empty() ? "password" : "noauth") << "\""
        << (settings.socks5Auth && !settings.socks5Username.empty()
            ? (std::string(", \"accounts\": [{ \"user\": \"") + settings.socks5Username
              + "\", \"pass\": \"" + settings.socks5Password + "\" }]")
            : "")
        << " },\n"
        << "    \"sniffing\": { \"enabled\": true, \"destOverride\": [\"http\",\"tls\"] }\n"
        << "  }],\n"
        << "  \"outbounds\": [{\n"
        << "    \"tag\": \"proxy\",\n";
    appendOutbound(oss, profile);
    oss << "\n  },{\n"
        << "    \"tag\": \"direct\",\n"
        << "    \"protocol\": \"freedom\",\n"
        << "    \"settings\": {}\n"
        << "  }],\n"
        << "  \"routing\": {\n"
        << "    \"domainStrategy\": \"IPIfNonMatch\",\n"
        << "    \"rules\": [{\n"
        << "      \"type\": \"field\",\n"
        << "      \"ip\": [\"geoip:private\"],\n"
        << "      \"outboundTag\": \"direct\"\n"
        << "    }]\n"
        << "  }\n"
        << "}\n";
    return oss.str();
}

// ── Start xray SOCKS5 listening on 0.0.0.0 for netns mode ─────────────────
bool launchXrayCoreForNetNS(const Settings& settings, const Profile& profile,
                            std::string& outLogFile, ProcessId& outPid) {
#if defined(__unix__) || defined(__APPLE__)
    std::string binaryPath = findXrayCoreBinary(settings);
    if (binaryPath.empty()) return false;

    std::string config = generateNetNSSocksConfig(profile, settings);
    std::ofstream cf("config_netns.json");
    if (!cf) return false;
    cf << config;
    cf.close();

    outLogFile = "xray-netns.log";
    std::string cmd = "nohup \"" + binaryPath + "\" -config config_netns.json >"
                    + outLogFile + " 2>&1 & echo $!";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[32] = {0};
    fgets(buf, sizeof(buf), p);
    pclose(p);
    outPid = strtol(buf, nullptr, 10);
    return outPid > 0;
#else
    (void)settings; (void)profile; (void)outLogFile; (void)outPid;
    return false;
#endif
}

// ── Get current (non-root) username ───────────────────────────────────────
#ifdef __linux__
static std::string getCurrentUser() {
    const char* u = getenv("SUDO_USER");
    if (u && u[0]) return u;
    u = getenv("USER");
    if (u && u[0]) return u;
    struct passwd* pw = getpwuid(getuid());
    if (pw) return pw->pw_name;
    return "";
}
#endif

// ── Create the VPN network namespace and start tun2socks ───────────────────
bool setupAppNetNS(int socksPort, Language lang) {
#ifdef __linux__
    std::cout << tr(lang,
        "Setting up VPN network namespace (requires sudo)...\n",
        "Настройка VPN сетевого пространства имён (требует sudo)...\n");

    // Tear down any previous state
    system(("sudo ip netns del " + NS_NAME + " 2>/dev/null").c_str());
    system(("sudo ip link del " + NS_VETH_H + " 2>/dev/null").c_str());
    usleep(200000);

    // 1. Create network namespace
    if (system(("sudo ip netns add " + NS_NAME).c_str()) != 0) {
        std::cout << tr(lang,
            "ERROR: cannot create network namespace. Is iproute2 installed and are you running with sudo?\n",
            "ОШИБКА: не удалось создать сетевое пространство имён. Установлен ли iproute2 и запущено ли с sudo?\n");
        return false;
    }

    // 2. veth pair: vl2h (host) ↔ vl2n (namespace)
    system(("sudo ip link add " + NS_VETH_H + " type veth peer name " + NS_VETH_N).c_str());
    system(("sudo ip link set " + NS_VETH_N + " netns " + NS_NAME).c_str());

    // 3. Configure host side of veth
    system(("sudo ip addr add " + NS_HOST_IP + "/24 dev " + NS_VETH_H).c_str());
    system(("sudo ip link set " + NS_VETH_H + " up").c_str());

    // 4. Configure namespace side of veth
    auto ns = [](const std::string& cmd) {
        system(("sudo ip netns exec " + NS_NAME + " " + cmd).c_str());
    };
    ns("ip addr add " + NS_NS_IP + "/24 dev " + NS_VETH_N);
    ns("ip link set " + NS_VETH_N + " up");
    ns("ip link set lo up");

    // 5. IP forwarding on host so namespace traffic can reach xray
    system("sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1");
    system(("sudo iptables -t nat -A POSTROUTING -s " + NS_SUBNET + " -j MASQUERADE 2>/dev/null").c_str());

    // 6. DNS for namespace via /etc/netns/<name>/resolv.conf
    //    (ip netns exec reads this file automatically when looking up names)
    system(("sudo mkdir -p /etc/netns/" + NS_NAME).c_str());
    {
        std::ofstream rc("/tmp/vl2_ns_resolv.conf");
        rc << "nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
    }
    system(("sudo cp /tmp/vl2_ns_resolv.conf /etc/netns/" + NS_NAME + "/resolv.conf").c_str());

    // 7. TUN device inside namespace (tun2socks will use this)
    ns("ip tuntap add mode tun name " + NS_TUN);
    ns("ip addr add 198.18.0.1/15 dev " + NS_TUN);   // tun2socks default range
    ns("ip link set " + NS_TUN + " up");

    // 8. Routing inside namespace:
    //    - veth route (10.200.0.0/24) stays direct → reach xray on host
    //    - everything else → through TUN (tun2socks handles it)
    ns("ip route add default dev " + NS_TUN);

    // 9. Start tun2socks inside the namespace.
    //    It reads from vl2tun and forwards all TCP/UDP via SOCKS5 to xray.
    //    xray listens on 0.0.0.0:port so it's reachable at 10.200.0.1:port.
    std::string t2sCmd =
        "sudo ip netns exec " + NS_NAME + " tun2socks"
        " -device "  + NS_TUN +
        " -proxy socks5://" + NS_HOST_IP + ":" + std::to_string(socksPort) +
        " -loglevel error"
        " >/tmp/vl2_tun2socks.log 2>&1 &";

    std::cout << tr(lang, "Starting tun2socks... ", "Запуск tun2socks... ");
    std::cout.flush();
    system(t2sCmd.c_str());
    usleep(1500000);   // let tun2socks initialise

    // 10. Quick connectivity test from inside the namespace
    int testRet = system(("sudo ip netns exec " + NS_NAME +
                          " ping -c 1 -W 4 8.8.8.8 >/dev/null 2>&1").c_str());
    if (testRet != 0) {
        std::cout << tr(lang, "FAIL\n", "ОШИБКА\n");
        std::cout << tr(lang,
            "Connectivity test failed. tun2socks log:\n",
            "Тест соединения не прошёл. Лог tun2socks:\n");
        system("tail -15 /tmp/vl2_tun2socks.log 2>/dev/null");
        std::cout << tr(lang,
            "\nNamespace is still set up — app may work even without ping.\n",
            "\nПространство имён всё ещё создано — приложение может работать несмотря на ошибку ping.\n");
    } else {
        std::cout << tr(lang, "OK\n", "OK\n");
    }

    // Save port for cleanup reference
    { std::ofstream f("/tmp/vl2_netns_port"); f << socksPort; }

    std::cout << tr(lang,
        "VPN namespace ready. ALL traffic from apps launched here goes through VLESS+Reality.\n",
        "VPN пространство имён готово. ВЕСЬ трафик запущенных приложений идёт через VLESS+Reality.\n");
    return true;
#else
    (void)socksPort; (void)lang;
    return false;
#endif
}

// ── Tear down the VPN namespace ────────────────────────────────────────────
void cleanupAppNetNS() {
#ifdef __linux__
    // Kill tun2socks
    system(("sudo ip netns exec " + NS_NAME + " pkill tun2socks 2>/dev/null").c_str());
    usleep(300000);

    // iptables cleanup
    system(("sudo iptables -t nat -D POSTROUTING -s " + NS_SUBNET + " -j MASQUERADE 2>/dev/null").c_str());

    // Delete namespace (also removes the veth peer inside it)
    system(("sudo ip netns del " + NS_NAME + " 2>/dev/null").c_str());
    // Remove host-side veth (may already be gone when namespace was deleted)
    system(("sudo ip link del " + NS_VETH_H + " 2>/dev/null").c_str());

    // Remove DNS override
    system(("sudo rm -rf /etc/netns/" + NS_NAME).c_str());
    system("rm -f /tmp/vl2_netns_port /tmp/vl2_ns_resolv.conf /tmp/vl2_tun2socks.log");
#endif
}

// ── Launch an app inside the VPN namespace as the current user ────────────
bool launchAppInNetNS(const std::string& command, Language lang) {
#ifdef __linux__
    clearScreen();
    std::cout << "=== " << tr(lang, "Launch in VPN namespace", "Запуск в VPN пространстве имён") << " ===\n\n";
    std::cout << tr(lang, "Command: ", "Команда: ") << command << "\n";
    std::cout << tr(lang,
        "ALL traffic from this app goes through VLESS+Reality.\n\n",
        "ВЕСЬ трафик этого приложения идёт через VLESS+Reality.\n\n");

    std::string user = getCurrentUser();
    if (user.empty()) {
        std::cout << tr(lang,
            "ERROR: cannot determine current user.\n",
            "ОШИБКА: не удалось определить текущего пользователя.\n");
        pauseScreen(tr(lang, "\nPress any key...", "\nЛюбая клавиша..."));
        return false;
    }

    // Collect display/session env vars so GUI apps work from inside netns.
    // Filesystem (X11/Wayland sockets) is shared — only network is isolated.
    std::string envStr;
    auto addEnv = [&](const char* var) {
        const char* v = getenv(var);
        if (v && v[0]) {
            envStr += std::string(var) + "='" + v + "' ";
        }
    };
    addEnv("DISPLAY");
    addEnv("WAYLAND_DISPLAY");
    addEnv("XDG_RUNTIME_DIR");
    addEnv("HOME");
    addEnv("DBUS_SESSION_BUS_ADDRESS");
    addEnv("XAUTHORITY");

    // Log file
    std::string appWord = command.substr(0, command.find(' '));
    appWord = appWord.substr(appWord.rfind('/') + 1);
    std::string logFile = "/tmp/vl2_ns_" + appWord + ".log";

    // ip netns exec runs as root; we drop back to the original user with sudo -u.
    // sh -c lets us set env vars as a preamble.
    std::string launchCmd =
        "nohup sudo ip netns exec " + NS_NAME +
        " sudo -u " + user + " -- sh -c '" + envStr + command + "'"
        " >'" + logFile + "' 2>&1 &";

    std::cout << tr(lang, "Launching...\n", "Запуск...\n");
    int ret = system(launchCmd.c_str());

    usleep(1500000);
    std::cout << tr(lang, "Log: ", "Лог: ") << logFile << "\n";
    std::cout << "\n--- " << tr(lang, "last output:", "последний вывод:") << " ---\n";
    system(("tail -8 '" + logFile + "' 2>/dev/null || echo '(no output yet)'").c_str());
    std::cout << "---\n";

    if (ret != 0) {
        std::cout << tr(lang,
            "\nWarning: launch returned non-zero exit code.\n",
            "\nПредупреждение: команда запуска вернула ненулевой код.\n");
    }

    pauseScreen(tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
    return true;
#else
    (void)command; (void)lang;
    return false;
#endif
}
