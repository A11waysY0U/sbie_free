// main.cpp — SandBoxie Unlocker Win32 GUI（纯 UI）
// ========================================================================
// 控件输入姓名/级别/天数，点击[开始注册]在工作线程执行 sbu::RunFlow，
// 点击[还原签名]执行 sbu::RunRestore。核心日志经回调转 UTF-16 显示到日志框。
// 特性：Common Controls v6 视觉样式、Per-Monitor DPI 感知、微软雅黑 UI 字体、
//       日志框等宽字体、窗口居中、流程运行期间禁用按钮。
// ========================================================================

#include <windows.h>
#include <shellapi.h>   // ShellExecuteA（WIN32_LEAN_AND_MEAN 下需显式包含）
#include <string>
#include <thread>
#include <cstdarg>
#include <cstdio>

#include "core.h"
#include "windows_security_check.h"

// 启用 Common Controls v6 视觉样式（按钮/编辑框/下拉框现代外观）
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ---------------- 控件 ID ----------------
#define IDC_NAME        101
#define IDC_LEVEL       102
#define IDC_DAYS        103
#define IDC_BTN_START   104
#define IDC_BTN_RESTORE 105
#define IDC_LOG         106

#define WM_FLOW_DONE    (WM_APP + 1)   // 流程结束，恢复按钮

static HWND g_hName = NULL, g_hLevel = NULL, g_hDays = NULL, g_hLog = NULL;
static HWND g_hBtnStart = NULL, g_hBtnRestore = NULL;
static HFONT g_hFontUi = NULL, g_hFontMono = NULL;

// ---------------- DPI 感知缩放 ----------------
static int GetDpi()
{
    static int dpi = 0;
    if (!dpi) dpi = GetDpiForSystem();
    return dpi;
}
static int S(int v) { return MulDiv(v, GetDpi(), 96); }

// 创建字体：pt 为磅值；mono 用于日志框（等宽）
static HFONT MakeFont(int pt, bool mono)
{
    const wchar_t* face = mono ? L"Consolas" : L"Microsoft YaHei UI";
    int px = -MulDiv(pt, GetDpi(), 72);
    return CreateFontW(px, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

static void ApplyFont(HWND hwnd, HFONT font)
{
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)font, TRUE);
}

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

// ---------------- 窗口居中 ----------------
static void CenterWindow(HWND hwnd)
{
    RECT rc; GetWindowRect(hwnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// ---------------- 流程启动（工作线程 + 结束恢复按钮） ----------------
static void StartFlowAsync(HWND hWnd, const std::string& name,
                           const std::string& level, long long days)
{
    EnableWindow(g_hBtnStart, FALSE);
    EnableWindow(g_hBtnRestore, FALSE);
    std::thread([hWnd, name, level, days]() {
        try { sbu::RunFlow(name, level, days); }
        catch (const std::exception& e) { UiLogF("[-] 异常: %s", e.what()); }
        UiLog("----------------------------------------");
        PostMessageW(hWnd, WM_FLOW_DONE, 0, 0);
    }).detach();
}

static void StartRestoreAsync(HWND hWnd)
{
    EnableWindow(g_hBtnStart, FALSE);
    EnableWindow(g_hBtnRestore, FALSE);
    std::thread([hWnd]() {
        try { sbu::RunRestore(); }
        catch (const std::exception& e) { UiLogF("[-] 异常: %s", e.what()); }
        UiLog("----------------------------------------");
        PostMessageW(hWnd, WM_FLOW_DONE, 0, 0);
    }).detach();
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        // 参数分组框
        int gy = S(12), boxH = S(132);
        CreateWindowW(L"BUTTON", L"证书参数", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            S(12), gy, S(376), boxH, hWnd, NULL, NULL, NULL);

        const int lx = S(30), ix = S(108), iw = S(262), ih = S(26);
        const int lw = S(72);
        int y = gy + S(26);

        CreateWindowW(L"STATIC", L"姓名:", WS_CHILD | WS_VISIBLE | SS_RIGHT,
            lx, y + S(5), lw, S(20), hWnd, NULL, NULL, NULL);
        g_hName = CreateWindowW(L"EDIT", L"Demo User",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            ix, y, iw, ih, hWnd, (HMENU)IDC_NAME, NULL, NULL);

        y += S(38);
        CreateWindowW(L"STATIC", L"级别:", WS_CHILD | WS_VISIBLE | SS_RIGHT,
            lx, y + S(5), lw, S(20), hWnd, NULL, NULL, NULL);
        g_hLevel = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | CBS_DROPDOWNLIST,
            ix, y, iw, S(220), hWnd, (HMENU)IDC_LEVEL, NULL, NULL);
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"STANDARD");
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"ADVANCED");
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"ADVANCED1");
        SendMessageW(g_hLevel, CB_ADDSTRING, 0, (LPARAM)L"HUGE");
        SendMessageW(g_hLevel, CB_SETCURSEL, 1, 0);

        y += S(38);
        CreateWindowW(L"STATIC", L"天数:", WS_CHILD | WS_VISIBLE | SS_RIGHT,
            lx, y + S(5), lw, S(20), hWnd, NULL, NULL, NULL);
        g_hDays = CreateWindowW(L"EDIT", L"365",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL,
            ix, y, iw, ih, hWnd, (HMENU)IDC_DAYS, NULL, NULL);

        // 操作按钮
        int by = gy + boxH + S(14);
        g_hBtnStart = CreateWindowW(L"BUTTON", L"开始注册",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            S(12), by, S(224), S(36), hWnd, (HMENU)IDC_BTN_START, NULL, NULL);
        g_hBtnRestore = CreateWindowW(L"BUTTON", L"还原签名",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            S(248), by, S(140), S(36), hWnd, (HMENU)IDC_BTN_RESTORE, NULL, NULL);

        // 日志框（等宽字体）
        int ly = by + S(46);
        g_hLog = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            S(12), ly, S(376), S(196), hWnd, (HMENU)IDC_LOG, NULL, NULL);

        // 应用字体
        ApplyFont(g_hName, g_hFontUi);
        ApplyFont(g_hLevel, g_hFontUi);
        ApplyFont(g_hDays, g_hFontUi);
        ApplyFont(g_hBtnStart, g_hFontUi);
        ApplyFont(g_hBtnRestore, g_hFontUi);
        ApplyFont(g_hLog, g_hFontMono);

        UiLog("[*] 填写姓名/级别/天数后点击 [开始注册]");
        UiLog("[*] 项目地址: https://github.com/A11waysY0U/sbie_free");
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
            if (sbu::CheckSecuritySoftware(hWnd)) break;
            StartFlowAsync(hWnd, nameA, levelA, days);
        } else if (LOWORD(wParam) == IDC_BTN_RESTORE) {
            SetWindowTextW(g_hLog, L"");
            UiLog("[*] 正在还原签名...");
            StartRestoreAsync(hWnd);
        }
        break;
    }
    case WM_FLOW_DONE:
        EnableWindow(g_hBtnStart, TRUE);
        EnableWindow(g_hBtnRestore, TRUE);
        break;
    case WM_CTLCOLORSTATIC: {
        // 标签/分组框背景与窗口一致，文字透明，避免白底
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    case WM_DESTROY:
        g_hLog = NULL;
        if (g_hFontUi) { DeleteObject(g_hFontUi); g_hFontUi = NULL; }
        if (g_hFontMono) { DeleteObject(g_hFontMono); g_hFontMono = NULL; }
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

    // Per-Monitor V2 DPI 感知（高 DPI 下界面清晰）
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // 注册日志回调（核心模块输出 -> 日志框）
    sbu::SetLogger(UiLog);

    // 创建字体：界面用微软雅黑 UI，日志框用等宽 Consolas
    g_hFontUi = MakeFont(9, false);
    g_hFontMono = MakeFont(9, true);

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"sbuGuiClass";
    RegisterClassW(&wc);

    // 客户区 400x412，按窗口样式换算含边框的窗口尺寸
    DWORD style = WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME;
    RECT rc = { 0, 0, S(400), S(412) };
    AdjustWindowRectEx(&rc, style, FALSE, 0);

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Sandboxie-Plus 证书一键工具",
        style, CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top, NULL, NULL, hInstance, NULL);
    if (!hwnd) return 0;
    CenterWindow(hwnd);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
