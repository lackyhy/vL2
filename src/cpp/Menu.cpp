#include "Menu.h"
#include "ConsoleUtils.h"
#include "Settings.h"
#include <iostream>

static void showSettingsScreen(const Settings& settings) {
    clearScreen();
    Language lang = settings.language;
    std::cout << "=== " << tr(lang, "Settings", "Настройки") << " ===\n\n";
    std::cout << "1. " << tr(lang, "Auto-start xray-core", "Автостарт xray-core") << ": "
              << (settings.autoStart ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
    std::cout << "2. " << tr(lang, "Use proxy", "Использовать прокси") << ": "
              << (settings.useProxy ? tr(lang, "ON", "ВКЛ") : tr(lang, "OFF", "ВЫКЛ")) << "\n";
    std::cout << "3. " << tr(lang, "Log level", "Уровень логирования") << ": " << settings.logLevel << "\n";
    std::cout << "4. " << tr(lang, "Language", "Язык") << ": " << languageName(settings.language) << "\n";
    std::cout << "5. " << tr(lang, "xray-core folder", "Папка xray-core") << ": " << settings.xrayCoreDir << "\n\n";
    std::cout << tr(lang, "Type a number to change the option, or press 0 to return.",
                         "Введите цифру для изменения опции или 0 для возвращения.") << "\n";
}

void showProfiles(const std::vector<Profile>& profiles, Language lang) {
    clearScreen();
    std::cout << "=== " << tr(lang, "Profiles", "Профили") << " ===\n\n";
    if (profiles.empty()) {
        std::cout << tr(lang, "No profiles available.", "Нет доступных профилей.") << "\n";
    } else {
        for (size_t i = 0; i < profiles.size(); ++i) {
            std::cout << i + 1 << ". " << profiles[i].name
                      << " (" << profiles[i].type << ") @ " << profiles[i].address << "\n";
        }
    }
    pauseScreen(lang, tr(lang, "\nPress any key to continue...", "\nНажмите любую клавишу для продолжения..."));
}

void editSettings(Settings& settings) {
    while (true) {
        showSettingsScreen(settings);
        int key = readKey();
        if (key == '0') {
            break;
        }
        if (key == '1') {
            settings.autoStart = !settings.autoStart;
        } else if (key == '2') {
            settings.useProxy = !settings.useProxy;
        } else if (key == '3') {
            settings.logLevel = (settings.logLevel % 5) + 1;
        } else if (key == '4') {
            settings.language = (settings.language == Language::EN ? Language::RU : Language::EN);
        } else if (key == '5') {
            showCursor();
            clearScreen();
            std::cout << tr(settings.language, "Enter xray-core folder path:", "Введите путь к папке xray-core:") << "\n";
            std::cout << tr(settings.language, "Default:", "По умолчанию:") << " " << settings.xrayCoreDir << "\n";
            std::cout << "> ";
            std::string path;
            std::getline(std::cin >> std::ws, path);
            if (!path.empty()) {
                settings.xrayCoreDir = path;
            }
            hideCursor();
        }
    }
}
