#ifndef VL2_MENU_H
#define VL2_MENU_H

#include <vector>
#include "Settings.h"

void showProfiles(const std::vector<Profile>& profiles, Language lang);
void editSettings(Settings& settings);

#endif // VL2_MENU_H
