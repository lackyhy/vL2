#include "ConsoleUtils.h"
#include <iostream>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <unistd.h>
#include <termios.h>
#endif

int readKey() {
#ifdef _WIN32
    int ch = _getch();
    if (ch == 0 || ch == 224) {
        int arrow = _getch();
        switch (arrow) {
            case 72: return 1001; // up
            case 80: return 1002; // down
            case 75: return 1004; // left
            case 77: return 1003; // right
            default: return 0;
        }
    }
    return ch;
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    int ch = getchar();
    if (ch == 27) {
        int next1 = getchar();
        if (next1 == 91) {
            int next2 = getchar();
            if (next2 == 65) ch = 1001;
            else if (next2 == 66) ch = 1002;
            else if (next2 == 67) ch = 1003;
            else if (next2 == 68) ch = 1004;
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
#endif
}

void clearScreen() {
#ifdef _WIN32
    std::system("cls");
#else
    if (std::system("clear") != 0) {
        std::cout << "\033[2J\033[H";
    }
    std::cout.flush();
#endif
}

void hideCursor() {
#ifdef _WIN32
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle != INVALID_HANDLE_VALUE) {
        CONSOLE_CURSOR_INFO info;
        if (GetConsoleCursorInfo(handle, &info)) {
            info.bVisible = FALSE;
            SetConsoleCursorInfo(handle, &info);
        }
    }
#else
    std::cout << "\033[?25l";
    std::cout.flush();
#endif
}

void showCursor() {
#ifdef _WIN32
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle != INVALID_HANDLE_VALUE) {
        CONSOLE_CURSOR_INFO info;
        if (GetConsoleCursorInfo(handle, &info)) {
            info.bVisible = TRUE;
            SetConsoleCursorInfo(handle, &info);
        }
    }
#else
    std::cout << "\033[?25h";
    std::cout.flush();
#endif
}

void pauseScreen(const std::string& message) {
    showCursor();
    std::cout << message;
    readKey();
    hideCursor();
}

std::string inputString(const std::string& prompt, Language lang) {
    showCursor();
    std::cout << prompt;
    std::string input;
    while (true) {
        int key = readKey();
        if (key == '\n' || key == '\r') {
            std::cout << "\n";
            break;
        } else if (key == 3) { // Ctrl+C
            input = ""; // cancel
            std::cout << "\n" << tr(lang, "Cancelled.", "Отменено.") << "\n";
            break;
        } else if (key == 127 || key == 8) { // backspace
            if (!input.empty()) {
                input.pop_back();
                std::cout << "\b \b";
            }
        } else if (key >= 32 && key <= 126) {
            input += (char)key;
            std::cout << (char)key;
        }
    }
    hideCursor();
    return input;
}
