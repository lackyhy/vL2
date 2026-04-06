#include <iostream>
#include <vector>
#include "ConsoleUtils.h"
#include "Menu.h"
#include "XrayLauncher.h"
#include "Settings.h"
#include "mFile.h"

int main() {
    std::vector<Profile> profiles = {
        {"Default VMess", "VMess", "vpn.example.com:443"},
        {"Fast Shadowsocks", "Shadowsocks", "ss.example.com:8388"}
    };
    Settings settings;
    int selected = 0;

    hideCursor();
    while (true) {
        clearScreen();
        std::cout << "=== " << mFile::APP_NAME << " " << mFile::APP_VERSION << " ===\n";
        std::cout << mFile::APP_DESCRIPTION << "\n\n";
        std::cout << tr(settings.language, "Use arrow keys or type a number to choose.", "Используйте стрелки или введите цифру для выбора.") << "\n";
        std::cout << tr(settings.language, "Press Enter to execute.", "Нажмите Enter для выполнения.") << "\n\n";

        std::vector<std::string> menuItems = {
            tr(settings.language, "Launch xray-core", "Запустить xray-core"),
            tr(settings.language, "Profiles", "Профили"),
            tr(settings.language, "Settings", "Настройки"),
            tr(settings.language, "Exit", "Выход")
        };

        for (size_t i = 0; i < menuItems.size(); ++i) {
            std::cout << (static_cast<int>(i) == selected ? "> " : "  ");
            std::cout << i + 1 << ". " << menuItems[i] << "\n";
        }

        int key = readKey();
        if (key == 1001) {
            selected = (selected - 1 + menuItems.size()) % menuItems.size();
        } else if (key == 1002) {
            selected = (selected + 1) % menuItems.size();
        } else if (key >= '1' && key <= '0' + static_cast<int>(menuItems.size())) {
            selected = key - '1';
            key = '\n';
        }

        if (key == '\n' || key == '\r') {
            switch (selected) {
                case 0:
                    launchXrayCore(settings);
                    break;
                case 1:
                    showProfiles(profiles, settings.language);
                    break;
                case 2:
                    showCursor();
                    editSettings(settings);
                    hideCursor();
                    break;
                case 3:
                    showCursor();
                    clearScreen();
                    std::cout << tr(settings.language, "Exit...", "Выход...") << "\n";
                    return 0;
            }
        }
    }

    return 0;
}
