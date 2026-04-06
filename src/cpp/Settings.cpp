#include "Settings.h"

const char* tr(Language lang, const char* en, const char* ru) {
    return lang == Language::RU ? ru : en;
}

std::string languageName(Language lang) {
    return lang == Language::RU ? "Русский" : "English";
}
