#ifndef VL2_MENU_H
#define VL2_MENU_H

#include <vector>
#include <string>
#include "Settings.h"

void showProfiles(const std::vector<Profile>& profiles, Language lang);
void editProfiles(std::vector<Profile>& profiles, Language lang);
void editSettings(Settings& settings);
void saveProfiles(const std::vector<Profile>& profiles);
void loadProfiles(std::vector<Profile>& profiles);
void saveSettings(const Settings& settings);
void loadSettings(Settings& settings);

#endif // VL2_MENU_H
