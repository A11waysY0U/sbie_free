#pragma once
// On-disk PE helpers: map an image via LoadLibraryExA(DONT_RESOLVE_DLL_REFERENCES)
// for pattern scanning + export lookups. No relocations applied - RVAs only.
// Copied from D:\Sandboxie\Astra64-RW\cpp\pe.h (header-only, no changes).

#include <cstdint>
#include <stdexcept>
#include <string>
#include <Windows.h>

namespace pe {

struct LoadedImage {
    uintptr_t base;
    size_t    size_of_image;
};

inline LoadedImage load_image(const char* name) {
    HMODULE h = LoadLibraryExA(name, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!h)
        throw std::runtime_error(std::string("LoadLibraryExA(") + name + ") failed");
    auto base = reinterpret_cast<uintptr_t>(h);
    auto lfanew = *reinterpret_cast<uint32_t*>(base + 0x3C);
    auto sz = *reinterpret_cast<uint32_t*>(base + lfanew + 0x18 + 0x38);
    return { base, static_cast<size_t>(sz) };
}

inline uint64_t export_rva(uintptr_t module_base, const char* name) {
    auto p = reinterpret_cast<uintptr_t>(
        GetProcAddress(reinterpret_cast<HMODULE>(module_base), name));
    if (!p) return 0;
    return p - module_base;
}

} // namespace pe
