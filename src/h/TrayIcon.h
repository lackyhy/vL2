#ifndef VL2_TRAY_ICON_H
#define VL2_TRAY_ICON_H

#include "Settings.h"
#include <string>

// TrayConfig holds the current runtime state passed into the tray
struct TrayConfig {
    int port;
    bool xrayRunning;
    bool logsEnabled;
    Language language;
    std::string logFile;   // path to active log, empty if none
};

// Returned by enterTrayMode() once the user interacts with the tray
struct TrayResult {
    bool restore;       // true = user clicked Restore; false = user clicked Exit
    bool logsEnabled;   // updated value after potential toggle
};

#ifdef _WIN32
// Hides the console, shows a system-tray icon, and runs a Windows message loop
// until the user clicks Restore or Exit from the right-click context menu.
TrayResult enterTrayMode(const TrayConfig& cfg);
#endif

#endif // VL2_TRAY_ICON_H
