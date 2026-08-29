// windows_security_check.cpp — 检测可能导致 RTCore64 内核操作 BSOD 的安全软件
// 在加载 RTCore64 驱动之前调用。检测到已知冲突软件时弹窗并返回 true（阻止加载）。

#include "windows_security_check.h"

#include <windows.h>
#include <tlhelp32.h>
#include <cwchar>

namespace {

// Known security software process names that may conflict with RTCore64.
// Match process names exactly to avoid substring false positives.
const wchar_t* kConflictingProcesses[] = {
    L"avp.exe",            // Kaspersky Endpoint/Internet Security
    L"kavfs.exe",          // Kaspersky File Server
    L"avpui.exe",          // Kaspersky UI
    L"ksdeui.exe",         // Kaspersky Safe Kids
    L"360tray.exe",        // 360 Safe Guard
    L"360safe.exe",        // 360 Safe Guard
    L"360sd.exe",          // 360 Antivirus
    L"zhudongfangyu.exe",  // 360 proactive defense
    L"hipsdaemon.exe",     // Huorong
    L"wsctrl.exe",         // Huorong
    L"usysdiag.exe",       // Huorong
};

bool EqualsIgnoreCase(const wchar_t* lhs, const wchar_t* rhs)
{
    return CompareStringOrdinal(lhs, -1, rhs, -1, TRUE) == CSTR_EQUAL;
}

bool IsProcessRunning(const wchar_t* processName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (EqualsIgnoreCase(pe.szExeFile, processName)) {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

} // anonymous namespace

namespace {

bool RegReadDword(HKEY root, const char* subkey, const char* valueName, DWORD& outValue)
{
    outValue = 0;
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;

    DWORD size = sizeof(DWORD);
    DWORD type = 0;
    LONG result = RegQueryValueExA(hKey, valueName, nullptr, &type,
                                   reinterpret_cast<BYTE*>(&outValue), &size);
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(DWORD);
}

// 检测内核隔离/HVCI（内存完整性）
bool IsHvciEnabled()
{
    DWORD v = 0;
    return RegReadDword(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        "Enabled", v) && v == 1;
}

// 检测易受攻击驱动阻止列表
bool IsVulnerableDriverBlocklistEnabled()
{
    DWORD v = 0;
    const bool present = RegReadDword(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        "VulnerableDriverBlocklistEnable", v);

    // The list is enabled by default on Windows 10 1803+; zero explicitly disables it.
    return !present || v != 0;
}

// 检测内核模式硬件强制堆栈保护
bool IsKernelStackProtectionEnabled()
{
    DWORD v = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelModeHardwareEnforcedStackProtection",
        "Enabled", v) && v == 1) return true;
    return false;
}

} // anonymous namespace

bool sbu::CheckSecuritySoftware(HWND hwndParent)
{
    // --- 1) 内核安全特性检测 ---
    wchar_t blockers[1024] = { 0 };

    if (IsHvciEnabled())
        wcscat_s(blockers, L"    • 内核隔离（内存完整性 / HVCI）\n");
    if (IsVulnerableDriverBlocklistEnabled())
        wcscat_s(blockers, L"    • 驱动安全（易受攻击驱动阻止列表）\n");
    if (IsKernelStackProtectionEnabled())
        wcscat_s(blockers, L"    • 内核模式硬件强制堆栈保护\n");

    if (blockers[0] != L'\0') {
        wchar_t msg[2048];
        swprintf_s(msg,
            L"检测到以下 Windows 内核安全特性已启用：\n\n%s\n"
            L"这些特性会阻止 RTCore64 驱动加载，或导致内核操作失败/蓝屏。\n"
            L"请在 Windows 安全中心 → 设备安全性 → 内核隔离 中关闭相关选项后重试。",
            blockers);
        MessageBoxW(hwndParent, msg, L"内核安全特性冲突",
            MB_OK | MB_ICONWARNING | MB_TOPMOST);
        return true; // 阻止加载
    }

    // --- 2) 第三方安全软件进程检测 ---
    for (auto* proc : kConflictingProcesses) {
        if (IsProcessRunning(proc)) {
            wchar_t msg[512];
            swprintf_s(msg,
                L"检测到安全软件: %s\n\n"
                L"该软件可能与 RTCore64 驱动冲突，导致系统蓝屏 (BSOD)。\n"
                L"已停止加载驱动，请关闭或卸载该软件后重试。",
                proc);
            MessageBoxW(hwndParent, msg, L"安全软件冲突警告",
                MB_OK | MB_ICONWARNING | MB_TOPMOST);
            return true; // 阻止加载
        }
    }

    // 未检测到已知冲突软件，仍然弹窗提醒
    MessageBoxW(hwndParent,
        L"请勿安装卡巴斯基，如有请卸载。\n\n"
        L"卡巴斯基等安全软件会导致驱动加载时失败或蓝屏。",
        L"提示", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
    return false; // 允许加载
}
