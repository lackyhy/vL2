#ifndef VL2_XRAY_LAUNCHER_H
#define VL2_XRAY_LAUNCHER_H

#include <string>
#include "Settings.h"

using ProcessId = long;

struct XrayProcessInfo {
    ProcessId pid = 0;
    std::string binaryPath;
    std::string listenAddress;
};

std::string findXrayCoreBinary(const Settings& settings);
std::string generateConfig(const Profile& profile);
std::string generateConfig(const Profile& profile, bool tunnelMode);
std::string generateConfig(const Profile& profile, bool tunnelMode, const std::string& proxyProtocol);
std::string generateConfig(const Profile& profile, bool tunnelMode, const std::string& proxyProtocol, int port);
// Full version with optional local SOCKS5 authentication.
std::string generateConfig(const Profile& profile, bool tunnelMode, const std::string& proxyProtocol, int port,
                           bool socks5Auth, const std::string& socks5Username, const std::string& socks5Password);
// Generates an xray TUN inbound config (xray v5+).
// Creates a real virtual network interface that intercepts all system traffic.
std::string generateTunConfig(const Profile& profile, const Settings& settings);
// instanceId: 1 = primary proxy (config.json / port proxyPort),
//             2 = second proxy  (config2.json / port proxy2Port)
bool launchXrayCore(const Settings& settings, const Profile& profile, bool tunnelMode, const std::string& proxyProtocol, std::string& outLogFile, std::string& outListenAddress, ProcessId& outPid, int instanceId = 1);
// Launch xray in TUN mode (creates virtual network interface).
bool launchXrayTun(const Settings& settings, const Profile& profile, std::string& outLogFile, std::string& outIfaceName, ProcessId& outPid);
bool stopXrayCore(ProcessId pid);
bool isXrayRunning(ProcessId pid);
void showXrayLog(const std::string& logFile, Language lang);
XrayProcessInfo findRunningXrayProcess();
bool setupSystemVPN(const Settings& settings, ProcessId xrayPid);
bool cleanupSystemVPN(const Settings& settings);
bool cleanupTunVPN(const Settings& settings);
bool downloadXrayCore(const Settings& settings);

// ── Per-app proxy ──────────────────────────────────────────────────────────
// Launch a command with SOCKS5/HTTP proxy environment variables injected,
// and optionally via proxychains-ng if available on the system.
// proxyPort: SOCKS5 port; httpProxyPort: HTTP proxy port (0 = disabled).
void launchAppThroughProxy(const std::string& command, int proxyPort,
                           int httpProxyPort, Language lang);

// Check whether proxychains-ng (proxychains4 / proxychains) is installed.
bool isProxychainsAvailable();

// Write a minimal proxychains config pointing to the local SOCKS5 proxy.
// Returns the path to the generated config file.
std::string writeProxychainsConfig(int proxyPort);

// ── VPN namespace mode (Linux only) ───────────────────────────────────────
// Routes ALL traffic from an app through xray via a network namespace +
// tun2socks. Works for every app including those ignoring env-var proxies.
// Requires: iproute2, tun2socks   (pacman -S iproute2 tun2socks)

// Returns true if all required tools are available (ip, tun2socks).
bool isNetNSModeAvailable();

// Generate xray SOCKS5 config that listens on 0.0.0.0 (all interfaces).
// Required for the namespace to reach xray on the host via the veth IP.
std::string generateNetNSSocksConfig(const Profile& profile, const Settings& settings);

// Start xray with the netns config (0.0.0.0 listen).
bool launchXrayCoreForNetNS(const Settings& settings, const Profile& profile,
                            std::string& outLogFile, ProcessId& outPid);

// Create the vl2ns network namespace, veth pair, tun device, and start
// tun2socks inside the namespace pointing at xray SOCKS5 on the host.
bool setupAppNetNS(int socksPort, Language lang);

// Tear down the VPN namespace, veth, and iptables rules.
void cleanupAppNetNS();

// Launch command inside the VPN namespace as the current (non-root) user.
bool launchAppInNetNS(const std::string& command, Language lang);

#endif // VL2_XRAY_LAUNCHER_H
