#ifndef VL2_CONSOLE_UTILS_H
#define VL2_CONSOLE_UTILS_H

#include <string>
#include "Settings.h"

int readKey();
void clearScreen();
void hideCursor();
void showCursor();
void pauseScreen(const std::string& message);
std::string inputString(const std::string& prompt, Language lang);

#endif // VL2_CONSOLE_UTILS_H
