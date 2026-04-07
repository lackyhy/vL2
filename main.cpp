#include "Menu.h"
#include "ConsoleUtils.h"
#include "Settings.h"
#include "XrayLauncher.h"
#include <iostream>
#include <vector>
#include <signal.h>

int main() {
    std::vector<Profile> profiles;
    Settings settings;

    // Ignore SIGINT to prevent Ctrl+C from closing the app
    signal(SIGINT, SIG_IGN);

    loadProfiles(profiles);

    int selected = 0;

    while (true) {
        clearScreen();
        std::cout << "=== vL2 Launcher ===\n";
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
                    if (profiles.empty()) {
                        clearScreen();
                        std::cout << tr(settings.language, "No profiles available. Add profiles first.", "Нет доступных профилей. Сначала добавьте профили.") << "\n";
                        pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
                    } else {
                        // Show profiles and select one
                        clearScreen();
                        std::cout << tr(settings.language, "Select profile to launch:", "Выберите профиль для запуска:") << "\n\n";
                        for (size_t i = 0; i < profiles.size(); ++i) {
                            std::cout << i + 1 << ". " << profiles[i].name << " (" << profiles[i].type << ")\n";
                        }
                        std::cout << "\n" << tr(settings.language, "Enter number (1-", "Введите номер (1-") << profiles.size() << "): ";
                        int choice;
                        std::cin >> choice;
                        if (choice >= 1 && choice <= static_cast<int>(profiles.size())) {
                            launchXrayCore(settings, profiles[choice - 1]);
                        } else {
                            std::cout << tr(settings.language, "Invalid choice.", "Неверный выбор.") << "\n";
                            pauseScreen(tr(settings.language, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
                        }
                    }
                    break;
                case 1:
                    editProfiles(profiles, settings.language);
                    saveProfiles(profiles);
                    break;
                case 2:
                    editSettings(settings);
                    break;
                case 3:
                    saveProfiles(profiles);
                    clearScreen();
                    std::cout << tr(settings.language, "Exit...", "Выход...") << "\n";
                    return 0;
            }
        }
    }

    return 0;
}
