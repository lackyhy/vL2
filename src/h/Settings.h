#ifndef VL2_SETTINGS_H
#define VL2_SETTINGS_H

#include <string>

struct Profile {
    std::string name;
    std::string type;
    std::string address;
};

enum class Language {
    EN,
    RU
};

const char* tr(Language lang, const char* en, const char* ru);
std::string languageName(Language lang);

struct Settings {
    bool autoStart = false;
    bool useProxy = true;
    int logLevel = 2;
    Language language = Language::EN;
    std::string xrayCoreDir = "./xray";
};

#endif // VL2_SETTINGS_H
