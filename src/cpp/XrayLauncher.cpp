#include "XrayLauncher.h"
#include "ConsoleUtils.h"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

static bool isExecutableFile(const fs::path& path) {
    return fs::exists(path) && fs::is_regular_file(path);
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
    std::vector<std::string> candidates = {"xray-core", "xray-core.exe"};
    for (const auto& path : buildSearchPaths(settings)) {
        if (fs::is_directory(path)) {
            for (const auto& name : candidates) {
                fs::path candidate = path / name;
                if (isExecutableFile(candidate)) {
                    return candidate.string();
                }
            }
        } else if (isExecutableFile(path)) {
            return path.string();
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

void launchXrayCore(const Settings& settings) {
    clearScreen();
    std::cout << "=== Launch xray-core ===\n\n";
    std::cout << "Searching xray-core binary...\n";

    std::string binaryPath = findXrayCoreBinary(settings);
    if (binaryPath.empty()) {
        std::cout << "Failed to find xray-core binary.\n";
        std::cout << "Put xray-core files into the folder and try again.\n";
        pauseScreen(settings.language, tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
        return;
    }

    std::cout << "Found xray-core: " << binaryPath << "\n";
    std::cout << "Testing xray-core availability...\n";

    std::string command;
#ifdef _WIN32
    command = "\"" + binaryPath + "\" -version >nul 2>&1";
#else
    command = "\"" + binaryPath + "\" -version >/dev/null 2>&1";
#endif
    int result = std::system(command.c_str());
    if (result != 0) {
        std::cout << "xray-core found, but test command failed.\n";
        std::cout << "Make sure the binary is executable.\n";
    } else {
        std::cout << "xray-core is available. Replace this call with the actual launch command.\n";
    }
    pauseScreen(settings.language, tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
}
