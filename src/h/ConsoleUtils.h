#ifndef VL2_CONSOLE_UTILS_H
#define VL2_CONSOLE_UTILS_H

#include <string>
#include "Settings.h"

int readKey();
void clearScreen();
void hideCursor();
void showCursor();
void pauseScreen(Language lang, const std::string& message);

#endif // VL2_CONSOLE_UTILS_H
