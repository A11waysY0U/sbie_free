# SandBoxie Unlocker

[![Build & Release](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml/badge.svg)](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml)

用于生成硬件锁定（节点锁定）的 Sandboxie-Plus 赞助者证书，并应用对应内存补丁的 Windows 图形界面工具。

**语言：** [English](README.md) | 简体中文

## 概述

SandBoxie Unlocker 会：

1. 读取当前机器的硬件标识。
2. 生成 ECC 密钥对和节点锁定的 `Certificate.dat`。
3. 加载 `RTCore64.sys`，并补丁 `SbieDrv.sys` 内存中的公钥。
4. 重签 Sandboxie 可执行文件的 `.sig`，使补丁后的驱动接受生成的证书。
5. 操作结束后移除临时驱动服务。

> **仅供学习与研究。** 驱动补丁只存在于内存中，系统重启后失效。修改 Windows 安全设置或加载存在漏洞的内核驱动可能导致系统不稳定甚至蓝屏。请仅在可以接受数据丢失的测试环境中使用。

## 安全检测

开始注册前，程序会检查：

- 内存完整性（HVCI）
- Microsoft 易受攻击驱动阻止列表
- 内核模式硬件强制堆栈保护
- 已知冲突安全软件，包括卡巴斯基、360 和火绒进程

检测到上述情况时，程序会阻止操作。当前实现中，如果无法创建进程快照，程序会按“未发现冲突进程”处理并继续。

## 目录结构

```text
.
├── CMakeLists.txt
├── README.md
├── README_zh.md
├── src/
│   ├── core.cpp                    # 证书生成、驱动补丁、重签与还原
│   ├── core.h
│   ├── main.cpp                    # Win32 GUI
│   ├── windows_security_check.cpp  # 驱动兼容性与安全软件检测
│   └── windows_security_check.h
└── third_party/
    ├── rtcore.h                    # RTCore64 ioctl 封装
    └── RTCore64.sys
```

## 环境要求

- Windows x64
- Visual Studio 2022 或 Build Tools 2022，包含 MSVC 工具链与 Windows SDK
- CMake 3.15 或更高版本
- `third_party/RTCore64.sys`

构建成功后，CMake 会自动把 `RTCore64.sys` 复制到可执行文件所在目录。

## 构建

### Visual Studio 生成器

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

输出：

```text
build\Release\SandBoxieUnlocker.exe
build\Release\RTCore64.sys
```

### Ninja 生成器

需要先初始化 x64 MSVC 环境。例如：

```powershell
cmd /c "call ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"" && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build"
```

输出：

```text
build\SandBoxieUnlocker.exe
build\RTCore64.sys
```

如果你使用其他 Visual Studio 版本，请相应调整 `vcvars64.bat` 路径。

## 使用方法

1. 把 `SandBoxieUnlocker.exe` 和 `RTCore64.sys` 放到 Sandboxie 安装目录。
2. 以管理员身份运行 `SandBoxieUnlocker.exe`；未提权时程序会自动请求 UAC。
3. 填写姓名，选择级别（`STANDARD` / `ADVANCED` / `ADVANCED1` / `HUGE`），并输入有效天数。
4. 点击 **注册**。
5. 如果生成的 `Certificate.dat` 不在安装目录，请把它复制到 Sandboxie-Plus 安装目录。
6. 重启 Sandboxie-Plus。

### 还原

点击 **还原签名** 可以：

- 将 `*.sig.bak` 恢复为 `*.sig`
- 移除 `Certificate.dat`
- 停止并删除临时 `RTCore64` 服务

## 生成文件

程序会在当前目录生成以下文件：

| 文件 | 说明 |
|---|---|
| `Certificate.dat` | 生成的 Sandboxie-Plus 证书 |
| `key.hex` | 用于签发证书的私钥 |
| `mypub.hex` | 证书使用的公钥 |
| `sbie_key_backup.bin` | 驱动原始公钥备份 |

请妥善保管 `key.hex` 和 `sbie_key_backup.bin`，并保留到所有改动完全还原为止。

## 故障排查

- **驱动加载失败：** 检查内存完整性、易受攻击驱动阻止列表或其他内核保护功能是否开启，并查看程序弹出的警告。
- **蓝屏风险：** 不要在卡巴斯基、360、火绒或其他低层级安全软件运行时使用本工具。
- **没有 UAC 提示：** 从资源管理器启动，或使用已提权的终端，并确认当前用户具有提权权限。
- **构建失败：** 确认已初始化 x64 MSVC 环境，并已安装 Windows SDK。

## 参与贡献

欢迎提交 Issue 和 Pull Request。修改代码时请保持 UI 与核心逻辑分离，并在提交前确认 Release 构建可以通过。