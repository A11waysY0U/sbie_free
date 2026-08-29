#pragma once
#include <windows.h>

namespace sbu {

// 检测可能导致 BSOD 的安全软件。
// 返回 true = 检测到冲突软件，阻止加载 RTCore64；
// 返回 false = 未检测到，允许加载（但已弹出提醒弹窗）。
bool CheckSecuritySoftware(HWND hwndParent);

} // namespace sbu
