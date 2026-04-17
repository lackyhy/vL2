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

#endif // VL2_XRAY_LAUNCHER_H
