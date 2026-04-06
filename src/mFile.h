#ifndef VL2_MFILE_H
#define VL2_MFILE_H

#include <string>

namespace mFile {
    static constexpr const char* APP_NAME = "vL2";
    static constexpr const char* APP_VERSION = "0.1.0";
    static constexpr const char* APP_BUILD = "alpha";
    static constexpr const char* APP_DEVELOPERS = "lcky";
    static constexpr const char* APP_COPYRIGHT = "2026";
    static constexpr const char* APP_DESCRIPTION = "Console interface for xray-core launcher";

    inline std::string appInfo() {
        return std::string(APP_NAME) + " " + APP_VERSION + " (" + APP_BUILD + ")\n"
            + "Developers: " + APP_DEVELOPERS + "\n"
            + APP_DESCRIPTION + "\n"
            + "Copyright © " + APP_COPYRIGHT;
    }
}

#endif // VL2_MFILE_H
