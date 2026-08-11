// main.cpp — Va2PaAstra Win32 GUI（纯 UI）
// ========================================================================
// 控件输入姓名/级别/天数，点击[注册]在工作线程执行 va2pa::RunFlow，
// 点击[还原]执行 va2pa::RunRestore。核心日志经回调转 UTF-16 显示到日志框，
// 全部使用 Unicode API（W 版本），避免中文乱码。
// ========================================================================

#include <windows.h>
#include <shellapi.h>   // ShellExecuteA（WIN32_LEAN_AND_MEAN 下需显式包含）
#include <string>
#include <thread>
#include <cstdarg>
#include <cstdio>

#include "core.h"

// ---------------- 控件 ID ----------------
#define IDC_NAME        101
#define IDC_LEVEL       102
#define IDC_DAYS        103
#define IDC_BTN_START   104
#define IDC_BTN_RESTORE 105
#define IDC_LOG         106

static HWND g_hName = NULL, g_hLevel = NULL, g_hDays = NULL, g_hLog = NULL;

// ---------------- 日志回调（UTF-8 -> UTF-16 -> SendMessageW） ----------------
static void UiLog(const char* line)
{
    if (!g_hLog) return;
    wchar_t wbuf[1024];
    MultiByteToWideChar(CP_UTF8, 0, line, -1, wbuf, 1024);
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)wbuf);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
}

static void UiLogF(const char* fmt, ...)
{
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    UiLog(buf);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        int y = 15;
        CreateWindowW(L"STATIC", L"姓名随便填:", WS_CHILD | WS_VISIBLE, 15, y + 4, 110, 20, hWnd, NULL, NULL, NULL);
        g_hName = CreateWindowW(L"EDIT", L"Demo User", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            130, y, 220, 24, hWnd, (HMENU)IDC_NAME, NULL, NULL);
        y += 42;
        CreateWindowW(L"STATIC", L"级别(huge最高):", WS_CHILD | WS_VISIBLE, 15, y + 4, 110, 20, hWnd, NULL, NULL, NULL);
        g_hLevel = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
            130, y, 220, 200, hWnd, (HMENU)IDC_LEVEL, NULL, NULL);
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"STANDARD");
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"ADVANCED");
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"ADVANCED1");
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"HUGE");
        SendMessageW(g_hLevel, CB_SETCURSEL, 1, 0);
        y += 42;
        CreateWindowW(L"STATIC", L"有效天数 (Days):", WS_CHILD | WS_VISIBLE, 15, y + 4, 110, 20, hWnd, NULL, NULL, NULL);
        g_hDays = CreateWindowW(L"EDIT", L"365", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER | ES_AUTOHSCROLL,
            130, y, 220, 24, hWnd, (HMENU)IDC_DAYS, NULL, NULL);
        y += 52;
        CreateWindowW(L"BUTTON", L"注册", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            130, y, 120, 30, hWnd, (HMENU)IDC_BTN_START, NULL, NULL);
        CreateWindowW(L"BUTTON", L"还原", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            260, y, 90, 30, hWnd, (HMENU)IDC_BTN_RESTORE, NULL, NULL);
        y += 45;
        g_hLog = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
            15, y, 340, 250, hWnd, (HMENU)IDC_LOG, NULL, NULL);
        UiLog("[*] 填写姓名/级别/天数后点击 [注册]");
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_BTN_START) {
            wchar_t name[256] = { 0 }, daysBuf[32] = { 0 }, level[64] = { 0 };
            GetWindowTextW(g_hName, name, 256);
            GetWindowTextW(g_hDays, daysBuf, 32);
            int sel = (int)SendMessageW(g_hLevel, CB_GETCURSEL, 0, 0);
            if (sel < 0) sel = 0;
            SendMessageW(g_hLevel, CB_GETLBTEXT, sel, (LPARAM)level);
            long long days = _wtoi64(daysBuf);
            if (!name[0] || days <= 0) { UiLog("[-] 请填写姓名和有效的天数"); break; }
            char nameA[256] = { 0 }, levelA[64] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, name, -1, nameA, sizeof(nameA), NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, level, -1, levelA, sizeof(levelA), NULL, NULL);
            SetWindowTextW(g_hLog, L"");
            std::thread([=]() {
                try { va2pa::RunFlow(nameA, levelA, days); }
                catch (const std::exception& e) { UiLogF("[-] 异常: %s", e.what()); }
                UiLog("----------------------------------------");
            }).detach();
        } else if (LOWORD(wParam) == IDC_BTN_RESTORE) {
            std::thread([]() {
                try { va2pa::RunRestore(); }
                catch (const std::exception& e) { UiLogF("[-] 异常: %s", e.what()); }
                UiLog("----------------------------------------");
            }).detach();
        }
        break;
    }
    case WM_DESTROY:
        g_hLog = NULL;
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// ---------------- 提权 ----------------
static bool IsElevated()
{
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te = { 0 }; DWORD size = 0;
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size)) elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    // 未提权则自动以管理员身份重启（UAC）
    if (!IsElevated()) {
        char exe[MAX_PATH];
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        ShellExecuteA(NULL, "runas", exe, NULL, NULL, SW_SHOWNORMAL);
        return 0;
    }

    // 注册日志回调（核心模块输出 -> 日志框）
    va2pa::SetLogger(UiLog);

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"Va2PaGuiClass";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Sandboxie-Plus 一键工具",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 385, 470, NULL, NULL, hInstance, NULL);
    if (!hwnd) return 0;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
