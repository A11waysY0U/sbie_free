cmake_minimum_required(VERSION 3.15)
project(Va2PaAstra LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 仅支持 MSVC（依赖 cl.exe 的 /utf-8 源码与 Windows SDK）
if(NOT MSVC)
    message(FATAL_ERROR "本项目需使用 MSVC (cl.exe) 工具链编译（如 Visual Studio 2022 或 Build Tools）")
endif()

# GUI 主程序（WIN32 自动设置 /SUBSYSTEM:WINDOWS，即无控制台窗口）
add_executable(Va2PaAstra WIN32
    src/main.cpp
    src/core.cpp
)

target_include_directories(Va2PaAstra PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/astra
)

target_compile_definitions(Va2PaAstra PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
)

target_compile_options(Va2PaAstra PRIVATE
    /utf-8   # 源码按 UTF-8 处理（含中文字面量）
    /O2      # 优化
)

target_link_libraries(Va2PaAstra PRIVATE
    psapi
    advapi32
    shell32
    bcrypt
    user32
    gdi32
)

# 若源码树中存在 ASTRA64.sys（Astra64-RW 目录），构建后自动拷到输出目录，
# 这样工具运行时可直接从自身目录加载驱动。
set(ASTRA64_SYS "${CMAKE_CURRENT_SOURCE_DIR}/../Astra64-RW/ASTRA64.sys")
if(EXISTS "${ASTRA64_SYS}")
    add_custom_command(TARGET Va2PaAstra POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${ASTRA64_SYS}" "$<TARGET_FILE_DIR:Va2PaAstra>/ASTRA64.sys"
        COMMENT "已复制 ASTRA64.sys 到输出目录")
endif()
