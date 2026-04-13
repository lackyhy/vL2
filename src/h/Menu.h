#ifndef VL2_MENU_H
#define VL2_MENU_H

#include <vector>
#include <string>
#include <functional>
#include "Settings.h"

void showProfiles(const std::vector<Profile>& profiles, Language lang);
void editProfiles(std::vector<Profile>& profiles, Language lang);
void editSettings(Settings& settings);
void saveProfiles(const std::vector<Profile>& profiles);
void loadProfiles(std::vector<Profile>& profiles);
void saveSettings(const Settings& settings);
void loadSettings(Settings& settings);

// Per-app proxy list — persist separately from main settings
void saveAppList(const Settings& settings);
void loadAppList(Settings& settings);

// Per-app proxy manager UI.
// startProxy: lambda called when proxy needs to start — must start xray and
//             update proxyPort/httpProxyPort, return true on success.
// proxyPort / httpProxyPort: in-out, updated if proxy is started inside the menu.
void editAppProxyList(Settings& settings,
                      const std::vector<Profile>& profiles,
                      std::function<bool(int&, int&)> startProxy,
                      int& proxyPort, int& httpProxyPort);

#endif // VL2_MENU_H
