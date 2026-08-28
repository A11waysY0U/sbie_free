# SandBoxie Unlocker — Sandboxie-Plus 赞助者证书一键工具（Win32 GUI）

为 Sandboxie-Plus 生成节点锁定（本机 HWID）的赞助者证书，并通过 RTCore64 驱动
把生成的公钥写入已加载的 `SbieDrv.sys` 内存（补丁），再重签可执行文件的 `.sig`，
使驱动信任本工具签发的证书。

> 仅供学习与研究。补丁仅作用于内存中的驱动映像，重启系统后失效。

## 项目结构

```
SandBoxieUnlocker/
├── CMakeLists.txt          # CMake 构建（MSVC 专用）
├── src/
│   ├── core.h              # 核心逻辑声明（日志回调接口）
│   ├── core.cpp            # 核心实现：证书生成 / 驱动补丁 / .sig 重签 / 还原
│   └── main.cpp            # Win32 GUI（纯 UI，日志经回调展示）
└── third_party/
    └── rtcore.h            # RTCore64.sys 驱动封装（虚拟地址 R/W）
```

设计要点：核心逻辑（`core.cpp`）与表现层（`main.cpp`）分离，核心通过
`sbu::SetLogger()` 注册的回调输出 UTF-8 日志，UI 将其转为 UTF-16 显示，
因此不存在 ANSI/GBK 乱码问题。

## 依赖

- Visual Studio 2022（MSVC x64，含 Windows SDK），CMake ≥ 3.15
- `RTCore64.sys`（MSI Afterburner 驱动，CVE-2019-16098）——
  构建时若源码树根目录存在该文件会自动复制到输出目录；工具运行时从自身目录加载。

## 构建

方式一：VS 生成器（输出到 `build/`）

```powershell
cd D:\sbie_free
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

方式二：命令行（需先初始化 MSVC 环境）

```powershell
cd D:\sbie_free
cmd /c "call ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"" && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build"
```

产物：`build\Release\SandBoxieUnlocker.exe`（+ 自动复制的 `RTCore64.sys`）。

## 使用

把 SandBoxieUnlocker.exe 放到 Sandboxie 安装目录

以管理员身份运行 `SandBoxieUnlocker.exe`（程序检测到未提权会自动请求 UAC）：

1. 填写姓名、选择级别（STANDARD / ADVANCED / ADVANCED1 / HUGE）、有效天数
2. 点击 [注册]：自动完成 读 HWID → 生成密钥 → 生成 `Certificate.dat`
   → 启动驱动 → 补丁公钥 → 重签 `.sig`
3. 把 `Certificate.dat` 放入 Sandboxie-Plus 安装目录后重启即可

[还原] 按钮：把安装目录下 `*.sig.bak` 拷回 `*.sig`，并移除 `Certificate.dat`。

运行会在当前目录生成：`Certificate.dat`（证书）、`key.hex`（私钥）、
`mypub.hex`（公钥）、`sbie_key_backup.bin`（驱动原公钥备份）。
