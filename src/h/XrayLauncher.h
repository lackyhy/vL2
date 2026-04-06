#ifndef VL2_XRAY_LAUNCHER_H
#define VL2_XRAY_LAUNCHER_H

#include <string>
#include "Settings.h"

std::string findXrayCoreBinary(const Settings& settings);
void launchXrayCore(const Settings& settings);

#endif // VL2_XRAY_LAUNCHER_H
