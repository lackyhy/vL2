#include "TrayIcon.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <cstring>

// ── Constants ──────────────────────────────────────────────────────────────
#define WM_VL2_TRAY   (WM_USER + 100)
#define IDM_INFO      9000   // grayed status line
#define IDM_PORT      9001   // grayed port line
#define IDM_LOGS      9002   // toggle
#define IDM_RESTORE   9003
#define IDM_EXIT      9004

// ── Module-level state (single tray instance) ──────────────────────────────
static const TrayConfig* g_cfg     = nullptr;
static bool              g_logs    = true;
static bool              g_restore = false;   // set true → message loop exits
static bool              g_exit    = false;   // set true → message loop exits

// ── Helpers ────────────────────────────────────────────────────────────────
static const char* tr2(const char* en, const char* ru) {
    return (g_cfg && g_cfg->language == Language::RU) ? ru : en;
}

static void copyStr(char* dst, size_t dstSize, const std::string& src) {
    memset(dst, 0, dstSize);
    src.copy(dst, dstSize - 1);
}

// ── Context menu ───────────────────────────────────────────────────────────
static void showContextMenu(HWND hWnd) {
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();

    // Status line (grayed)
    std::string status = tr2("vL2 — xray not running", "vL2 — xray не запущен");
    if (g_cfg->xrayRunning) {
        status = tr2("vL2 — running", "vL2 — работает");
    }
    AppendMenuA(hMenu, MF_STRING | MF_GRAYED, IDM_INFO, status.c_str());

    // Port line (shown only when xray is active)
    if (g_cfg->xrayRunning) {
        std::string portLine = tr2("Port: ", "Порт: ");
        portLine += std::to_string(g_cfg->port);
        AppendMenuA(hMenu, MF_STRING | MF_GRAYED, IDM_PORT, portLine.c_str());
    }

    AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);

    // Logs toggle
    std::string logsLabel = tr2("Logs: ", "Логи: ");
    logsLabel += (g_logs ? tr2("ON", "ВКЛ") : tr2("OFF", "ВЫКЛ"));
    UINT logsFlags = MF_STRING;
    if (g_logs) logsFlags |= MF_CHECKED;
    AppendMenuA(hMenu, logsFlags, IDM_LOGS, logsLabel.c_str());

    AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);

    // Restore (bold — default action)
    AppendMenuA(hMenu, MF_STRING, IDM_RESTORE, tr2("Restore", "Восстановить"));
    SetMenuDefaultItem(hMenu, IDM_RESTORE, FALSE);

    // Exit
    AppendMenuA(hMenu, MF_STRING, IDM_EXIT, tr2("Exit", "Выход"));

    // TrackPopupMenu requires the window to be in the foreground
    SetForegroundWindow(hWnd);
    int cmd = TrackPopupMenu(hMenu,
                             TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                             pt.x, pt.y, 0, hWnd, nullptr);
    DestroyMenu(hMenu);

    // Post a dummy message so the menu disappears cleanly (Windows quirk)
    PostMessage(hWnd, WM_NULL, 0, 0);

    switch (cmd) {
        case IDM_RESTORE:
            g_restore = true;
            PostQuitMessage(0);
            break;
        case IDM_EXIT:
            g_exit = true;
            PostQuitMessage(0);
            break;
        case IDM_LOGS:
            g_logs = !g_logs;
            break;
        default:
            break;
    }
}

// ── Window procedure ───────────────────────────────────────────────────────
static LRESULT CALLBACK TrayWndProc(HWND hWnd, UINT msg,
                                    WPARAM wParam, LPARAM lParam) {
    if (msg == WM_VL2_TRAY) {
        UINT ev = LOWORD(lParam);
        if (ev == WM_RBUTTONUP) {
            showContextMenu(hWnd);
        } else if (ev == WM_LBUTTONDBLCLK) {
            // Double-click = restore
            g_restore = true;
            PostQuitMessage(0);
        }
        return 0;
    }
    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

// ── Public API ─────────────────────────────────────────────────────────────
TrayResult enterTrayMode(const TrayConfig& cfg) {
    g_cfg     = &cfg;
    g_logs    = cfg.logsEnabled;
    g_restore = false;
    g_exit    = false;

    // ── Hide console window ─────────────────────────────────────────────
    HWND hConsole = GetConsoleWindow();
    if (hConsole) ShowWindow(hConsole, SW_HIDE);

    // ── Register a message-only window class ────────────────────────────
    static const char* kClassName = "VL2TrayWnd";
    WNDCLASSA wc     = {};
    wc.lpfnWndProc   = TrayWndProc;
    wc.hInstance     = GetModuleHandleA(nullptr);
    wc.lpszClassName = kClassName;
    RegisterClassA(&wc);   // ignore "already registered" error on re-entry

    HWND hWnd = CreateWindowA(kClassName, "", 0,
                              0, 0, 0, 0,
                              HWND_MESSAGE,         // message-only, no taskbar entry
                              nullptr,
                              GetModuleHandleA(nullptr),
                              nullptr);

    // ── Build tray icon ─────────────────────────────────────────────────
    // Try to load the app's own icon first; fall back to generic one
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    HICON hIcon = ExtractIconA(GetModuleHandleA(nullptr), exePath, 0);
    if (!hIcon || hIcon == reinterpret_cast<HICON>(1ULL)) {
        hIcon = LoadIconA(nullptr, reinterpret_cast<LPCSTR>(IDI_APPLICATION));
    }

    NOTIFYICONDATAA nid = {};
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = hWnd;
    nid.uID              = 1;
    nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_VL2_TRAY;
    nid.hIcon            = hIcon;

    std::string tip = "vL2";
    if (cfg.xrayRunning) {
        tip += "  :";
        tip += std::to_string(cfg.port);
    }
    copyStr(nid.szTip, sizeof(nid.szTip), tip);

    Shell_NotifyIconA(NIM_ADD, &nid);

    // ── Balloon notification ────────────────────────────────────────────
    nid.uFlags     = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    nid.uTimeout   = 2500;
    copyStr(nid.szInfoTitle, sizeof(nid.szInfoTitle), "vL2");
    std::string balloonText =
        (cfg.language == Language::RU)
            ? "Приложение свёрнуто. ПКМ по иконке для управления."
            : "App minimized. Right-click the icon to manage.";
    copyStr(nid.szInfo, sizeof(nid.szInfo), balloonText);
    Shell_NotifyIconA(NIM_MODIFY, &nid);

    // ── Windows message loop (blocks here until user acts) ──────────────
    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
        if (g_restore || g_exit) break;
    }

    // ── Cleanup tray icon ───────────────────────────────────────────────
    nid.uFlags = 0;
    Shell_NotifyIconA(NIM_DELETE, &nid);
    if (hIcon && hIcon != reinterpret_cast<HICON>(1ULL)) {
        DestroyIcon(hIcon);
    }

    DestroyWindow(hWnd);
    UnregisterClassA(kClassName, GetModuleHandleA(nullptr));

    // ── Restore or exit ─────────────────────────────────────────────────
    TrayResult result;
    result.restore     = g_restore;
    result.logsEnabled = g_logs;

    if (g_restore && hConsole) {
        ShowWindow(hConsole, SW_SHOW);
        SetForegroundWindow(hConsole);
    }

    return result;
}

#endif // _WIN32
