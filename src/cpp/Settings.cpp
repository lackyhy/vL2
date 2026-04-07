#include "Settings.h"

std::string tr(Language lang, const std::string& en, const std::string& ru) {
    return lang == Language::RU ? ru : en;
}

std::string languageName(Language lang) {
    return lang == Language::RU ? "Русский" : "English";
}
