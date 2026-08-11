#pragma once
// Va2PaAstra 核心逻辑声明（与 UI 解耦）
//
// 核心模块提供：证书生成 / 驱动补丁 / .sig 重签 / 还原。
// 所有输出经日志回调上报（UTF-8 单行文本，不含换行），UI 自行决定如何展示。

#include <string>

namespace va2pa {

// 日志回调类型：接收一行 UTF-8 文本（无结尾换行）
using LogFn = void (*)(const char* line);

// 设置日志回调（可为 nullptr 关闭日志）
void SetLogger(LogFn fn);

// 一键流程：
//   读本机 SMBIOS UUID(HWID) -> 生成 ECDSA P-256 密钥 -> 生成 Certificate.dat
//   -> 启动 ASTRA64 驱动 -> 补丁 SbieDrv.sys 内存公钥 -> 重签 <exe>.sig
// 生成的证书/密钥文件写入当前工作目录。
void RunFlow(const std::string& name, const std::string& level, long long days);

// 还原：把安装目录下 *.sig.bak 拷回 *.sig，并移除 Certificate.dat。
void RunRestore();

} // namespace va2pa
