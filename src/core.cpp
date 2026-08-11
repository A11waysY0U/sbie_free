// core.cpp — Va2PaAstra 核心逻辑实现
// ========================================================================
// 证书生成 / 驱动服务管理 / SbieDrv.sys 公钥补丁 / .sig 重签 / 还原。
// 所有日志经 va2pa::Log（回调）输出 UTF-8 单行文本，与 UI 解耦。
// ========================================================================

#include "core.h"

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <cstdarg>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <ctime>
#include <algorithm>
#include <fstream>
#include <stdexcept>

#include "astra.h"
#include "kernel.h"

namespace va2pa {

// ---------------- 常量 ----------------
static const char* SOFTWARE_NAME = "Sandboxie-Plus";

static const BYTE  kEcs1[]   = { 0x45, 0x43, 0x53, 0x31 }; // "ECS1" 特征
static const SIZE_T kEcs1Len = 4;

static const ULONG kEcdsaPublicMagic = 0x31534345; // "ECS1"

// ---------------- 日志（回调，UTF-8 单行） ----------------
static LogFn g_log = nullptr;

void SetLogger(LogFn fn) { g_log = fn; }

static void Log(const char* fmt, ...)
{
    if (!g_log) return;
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    g_log(buf);
}

// ---------------- 工具函数 ----------------
static void ThrowIf(NTSTATUS st, const char* what) {
    if (st != 0) throw std::runtime_error(std::string(what) + " (0x" +
        [&]{ char b[16]; snprintf(b, sizeof(b), "%08X", (unsigned)st); return std::string(b); }() + ")");
}

static std::string ToUpper(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::toupper);
    return r;
}

static std::string Hex(const std::vector<BYTE>& d) {
    static const char* h = "0123456789ABCDEF";
    std::string r; r.reserve(d.size() * 2);
    for (BYTE b : d) { r += h[b >> 4]; r += h[b & 0xF]; }
    return r;
}

static std::vector<BYTE> Sha256(const std::vector<BYTE>& data) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
    ThrowIf(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0), "SHA256 open");
    DWORD cbHash = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(cbHash), &cbData, 0);
    std::vector<BYTE> hash(cbHash);
    ThrowIf(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0), "SHA256 create");
    if (!data.empty())
        ThrowIf(BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0), "SHA256 hash");
    ThrowIf(BCryptFinishHash(hHash, hash.data(), cbHash, 0), "SHA256 finish");
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

static std::string Base64Encode(const std::vector<BYTE>& data) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        unsigned n = (unsigned)data[i] << 16;
        if (i + 1 < data.size()) n |= (unsigned)data[i + 1] << 8;
        if (i + 2 < data.size()) n |= (unsigned)data[i + 2];
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += (i + 1 < data.size()) ? tbl[(n >> 6) & 63] : '=';
        out += (i + 2 < data.size()) ? tbl[n & 63] : '=';
    }
    return out;
}

static void HexDump(const BYTE* buf, SIZE_T len) {
    std::string s;
    char tmp[8];
    for (SIZE_T i = 0; i < len; i++) {
        snprintf(tmp, sizeof(tmp), "%02X ", buf[i]);
        s += tmp;
        if ((i + 1) % 16 == 0) { Log("    %s", s.c_str()); s.clear(); }
    }
    if (!s.empty()) Log("    %s", s.c_str());
}

// ---------------- 密钥生成 / 签名 (CNG) ----------------
static void GenerateKeyPair(std::vector<BYTE>& privBlob, std::vector<BYTE>& pubBlob) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    ThrowIf(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0), "keygen open");
    ThrowIf(BCryptGenerateKeyPair(hAlg, &hKey, 256, 0), "keygen gen");
    ThrowIf(BCryptFinalizeKeyPair(hKey, 0), "keygen finalize");

    DWORD cb = 0;
    BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &cb, 0);
    privBlob.resize(cb);
    ThrowIf(BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, privBlob.data(), cb, &cb, 0), "keygen export priv");
    BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cb, 0);
    pubBlob.resize(cb);
    ThrowIf(BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pubBlob.data(), cb, &cb, 0), "keygen export pub");

    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
}

static std::vector<BYTE> SignDigest(const std::vector<BYTE>& privBlob, const std::vector<BYTE>& digest) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    ThrowIf(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0), "sign open");
    ThrowIf(BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &hKey,
        (PUCHAR)privBlob.data(), (ULONG)privBlob.size(), 0), "sign import");
    DWORD cbSig = 0;
    ThrowIf(BCryptSignHash(hKey, NULL, (PUCHAR)digest.data(), (ULONG)digest.size(), NULL, 0, &cbSig, 0), "sign size");
    std::vector<BYTE> sig(cbSig);
    ThrowIf(BCryptSignHash(hKey, NULL, (PUCHAR)digest.data(), (ULONG)digest.size(), sig.data(), cbSig, &cbSig, 0), "sign");
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    return sig;
}

// ---------------- 本机 SMBIOS UUID（与驱动 InitFwUuid 一致） ----------------
static std::string GetLocalUUID() {
    UINT size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0) return "";
    std::vector<BYTE> buf(size);
    if (GetSystemFirmwareTable('RSMB', 0, buf.data(), size) == 0) return "";
    if (buf.size() < 8) return "";

    BYTE* p = buf.data() + 8;
    BYTE* end = buf.data() + size;

    while (p + 4 <= end) {
        BYTE type = p[0];
        BYTE len = p[1];
        if (len < 4) break;
        if (type == 1 && len >= 0x19) {
            BYTE* raw = p + 8;
            bool allZero = true, allOne = true;
            for (int i = 0; i < 16; i++) {
                if (raw[i] != 0x00) allZero = false;
                if (raw[i] != 0xFF) allOne = false;
            }
            if (allZero || allOne) break;

            BYTE u[16];
            u[0]=raw[3]; u[1]=raw[2]; u[2]=raw[1]; u[3]=raw[0];
            u[4]=raw[5]; u[5]=raw[4];
            u[6]=raw[7]; u[7]=raw[6];
            for (int i = 8; i < 16; i++) u[i] = raw[i];

            char b[64];
            sprintf_s(b, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                u[0],u[1],u[2],u[3], u[4],u[5], u[6],u[7], u[8],u[9], u[10],u[11],u[12],u[13],u[14],u[15]);
            return b;
        }
        p += len;
        while (p + 1 < end && !(p[0] == 0 && p[1] == 0)) p++;
        p += 2;
    }
    return "";
}

// ---------------- 证书生成（固定 PERSONAL-<level>，HWID 节点锁定） ----------------
static std::vector<std::string> OptionsForLevel(const std::string& lv) {
    std::string u = ToUpper(lv);
    if (u == "HUGE" || u == "MAX" || u == "ETERNAL") return { "SBOX", "EBOX", "NETI", "DESK" };
    if (u == "ADVANCED")  return { "SBOX", "EBOX", "NETI" };
    if (u == "ADVANCED1") return { "SBOX", "EBOX" };
    return { "SBOX" }; // STANDARD / STANDARD2 / 其它
}

static std::string BuildCertificate(const std::string& name, const std::string& level,
                                    long long days, const std::string& hwid,
                                    const std::vector<BYTE>& privBlob, bool bom)
{
    std::vector<std::string> lines;
    lines.push_back("NAME: " + name);

    time_t now = time(nullptr); std::tm t; gmtime_s(&t, &now);
    char dbuf[64];
    snprintf(dbuf, sizeof(dbuf), "%02d.%02d.%04d+%lld", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, days);
    lines.push_back("DATE: " + std::string(dbuf));

    lines.push_back("TYPE: PERSONAL-" + ToUpper(level));

    auto options = OptionsForLevel(level);
    if (!options.empty()) {
        std::string o;
        for (size_t i = 0; i < options.size(); i++) { if (i) o += ", "; o += options[i]; }
        lines.push_back("OPTIONS: " + o);
    }
    lines.push_back("HWID: " + hwid);
    lines.push_back("SOFTWARE: " + std::string(SOFTWARE_NAME));

    // 哈希（SIGNATURE 不参与）
    std::vector<BYTE> input;
    for (auto& ln : lines) {
        size_t pos = ln.find(':');
        std::string nm = ln.substr(0, pos); while (!nm.empty() && (nm.back()==' '||nm.back()=='\t')) nm.pop_back();
        std::string vl = ln.substr(pos + 1); size_t s=vl.find_first_not_of(" \t"); if (s!=std::string::npos) vl = vl.substr(s); else vl="";
        input.insert(input.end(), nm.begin(), nm.end());
        input.insert(input.end(), vl.begin(), vl.end());
    }
    std::vector<BYTE> digest = Sha256(input);
    std::vector<BYTE> sig = SignDigest(privBlob, digest);

    std::string text;
    for (auto& ln : lines) text += ln + "\r\n";
    text += "SIGNATURE: " + Base64Encode(sig) + "\r\n";
    if (bom) text = "\xEF\xBB\xBF" + text;
    return text;
}

// ---------------- 页表 / 内核（Astra64） ----------------
static bool TranslateVaToPa(const astra::Astra& drv, uint64_t cr3, uint64_t va, uint64_t& outPa, bool verbose)
{
    uint64_t idx[4] = { (va >> 39) & 0x1FF, (va >> 30) & 0x1FF, (va >> 21) & 0x1FF, (va >> 12) & 0x1FF };
    const char* names[4] = { "PML4", "PDPT", "PD", "PT" };

    uint64_t tablePa = cr3 & 0x000FFFFFFFFFF000ULL;
    for (int lvl = 0; lvl < 4; lvl++) {
        uint64_t ptePa = tablePa + idx[lvl] * 8;
        uint64_t entry;
        try { entry = drv.read_u64(ptePa); } catch (...) { if (verbose) Log("    %s 读取失败", names[lvl]); return false; }
        bool present = (entry & 1) != 0;
        bool large = (entry & 0x80) && (lvl == 1 || lvl == 2);
        if (verbose)
            Log("    %s[0x%llX] 槽位PA=0x%llX 项=0x%llX P=%d PS=%d",
                names[lvl], idx[lvl], ptePa, entry, present ? 1 : 0, (entry & 0x80) ? 1 : 0);
        if (!present) return false;
        if (large) {
            if (lvl == 1) outPa = (entry & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
            else          outPa = (entry & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
            if (verbose) Log("    ^ 命中%s 大页", (lvl == 2) ? " 2MB" : " 1GB");
            return true;
        }
        tablePa = entry & 0x000FFFFFFFFFF000ULL;
    }
    outPa = tablePa + (va & 0xFFF);
    return true;
}

static uint64_t FindKernelCr3(const astra::Astra& drv, uint64_t knownKernelVa)
{
    const uint64_t kusdPml4Idx = (astra::KUSD_VA >> 39) & 0x1FF;
    std::vector<uint64_t> candidates;
    for (uint64_t phys_page = 0; phys_page < 0x4000000ULL; phys_page += 0x1000) {
        uint64_t pml4e;
        try { pml4e = drv.read_u64(phys_page + kusdPml4Idx * 8); } catch (...) { continue; }
        if (!(pml4e & 1)) continue;
        if ((pml4e & 0x000FFFFFFFFFF000ULL) > 0x800000000ULL) continue;
        candidates.push_back(phys_page);
    }
    for (auto cr3 : candidates) {
        uint64_t kusdPa;
        if (!kernel::virt_to_phys(drv, cr3, astra::KUSD_VA, kusdPa)) continue;
        try { if (drv.read_u32(kusdPa + 0x26C) != 10) continue; } catch (...) { continue; }
        uint64_t pa;
        if (kernel::virt_to_phys(drv, cr3, knownKernelVa, pa)) return cr3;
    }
    return 0;
}

static uint64_t GetDriverBase(const char* name)
{
    LPVOID drivers[1024];
    DWORD cb = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) return 0;
    int n = (int)(cb / sizeof(LPVOID));
    char buf[MAX_PATH];
    for (int i = 0; i < n; i++) {
        if (!drivers[i]) continue;
        if (GetDeviceDriverBaseNameA(drivers[i], buf, sizeof(buf)) && _stricmp(buf, name) == 0)
            return (uint64_t)drivers[i];
    }
    return 0;
}

static bool GetImageSize(const astra::Astra& drv, uint64_t cr3, uint64_t baseVa, uint64_t& size)
{
    uint64_t basePa;
    if (!TranslateVaToPa(drv, cr3, baseVa, basePa, false)) return false;
    BYTE hdr[0x400];
    try { drv.read_phys(basePa, hdr, sizeof(hdr)); } catch (...) { return false; }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    size = nt->OptionalHeader.SizeOfImage;
    return true;
}

static bool ScanImageForSig(const astra::Astra& drv, uint64_t cr3, uint64_t baseVa,
                            uint64_t imageSize, uint64_t& outVa, uint64_t& outPa)
{
    const SIZE_T kPage = 0x1000;
    BYTE page[0x1000];
    for (uint64_t va = baseVa; va < baseVa + imageSize; va += kPage) {
        uint64_t pagePa;
        if (!TranslateVaToPa(drv, cr3, va, pagePa, false)) continue;
        try { drv.read_phys(pagePa, page, kPage); } catch (...) { continue; }
        for (SIZE_T i = 0; i + kEcs1Len <= kPage; i++)
            if (memcmp(page + i, kEcs1, kEcs1Len) == 0) {
                outVa = va + i; outPa = pagePa + i; return true;
            }
    }
    return false;
}

// ---------------- 驱动服务：检查 / 创建 / 启动 ----------------
static std::string FindDriverFile()
{
    char exe[MAX_PATH]; GetModuleFileNameA(NULL, exe, MAX_PATH);
    std::string dir = exe; dir = dir.substr(0, dir.find_last_of("\\/"));
    std::vector<std::string> cands = {
        dir + "\\ASTRA64.sys",                          // exe 同目录
    };
    for (auto& c : cands)
        if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) return c;
    return "";
}

static bool EnsureAstraDriver()
{
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) { Log("[-] OpenSCManager 失败 (%lu)", GetLastError()); return false; }

    SC_HANDLE hSvc = OpenServiceA(hSCM, "ASTRA64", SERVICE_ALL_ACCESS);
    if (!hSvc) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::string drvPath = FindDriverFile();
            if (drvPath.empty()) { Log("[-] 未找到 ASTRA64.sys"); CloseServiceHandle(hSCM); return false; }
            Log("[.] 服务不存在，从 %s 创建...", drvPath.c_str());
            hSvc = CreateServiceA(hSCM, "ASTRA64", "ASTRA64", SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                drvPath.c_str(), NULL, NULL, NULL, NULL, NULL);
            if (!hSvc) { Log("[-] CreateService 失败 (%lu)", GetLastError()); CloseServiceHandle(hSCM); return false; }
        } else {
            Log("[-] OpenService 失败 (%lu)", GetLastError());
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    SERVICE_STATUS ss = { 0 };
    if (!QueryServiceStatus(hSvc, &ss)) {
        Log("[-] QueryServiceStatus 失败 (%lu)", GetLastError());
        CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
        return false;
    }
    if (ss.dwCurrentState == SERVICE_RUNNING) {
        Log("[+] ASTRA64 服务已运行");
    } else {
        Log("[.] 启动 ASTRA64 服务...");
        if (!StartServiceA(hSvc, 0, NULL)) {
            DWORD e = GetLastError();
            if (e != ERROR_SERVICE_ALREADY_RUNNING) {
                Log("[-] StartService 失败 (%lu)", e);
                CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
                return false;
            }
        }
        for (int i = 0; i < 30; i++) {
            Sleep(100);
            if (QueryServiceStatus(hSvc, &ss) && ss.dwCurrentState == SERVICE_RUNNING) break;
        }
        if (ss.dwCurrentState != SERVICE_RUNNING) {
            Log("[-] 服务未进入运行状态 (state=%lu)", ss.dwCurrentState);
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
            return false;
        }
        Log("[+] ASTRA64 服务已启动");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return true;
}

static bool OpenAstra(astra::Astra& drv)
{
    try { drv.open(); return true; } catch (...) {}
    Log("[.] ASTRA64 驱动未运行，检查/创建/启动服务...");
    if (EnsureAstraDriver()) {
        try { drv.open(); return true; } catch (...) {}
    }
    return false;
}

static bool SaveRawFile(const char* path, const BYTE* data, size_t len)
{
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    return w == len;
}

// ---------------- 重新签名可执行文件（生成 <exe>.sig） ----------------
static bool SignFile(const std::string& exePath, const std::vector<BYTE>& privBlob)
{
    std::ifstream ifs(exePath, std::ios::binary);
    if (!ifs) return false;
    std::vector<BYTE> content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();
    if (content.empty()) return false;

    std::vector<BYTE> digest = Sha256(content);
    std::vector<BYTE> sig = SignDigest(privBlob, digest); // 原始 R||S 64B

    std::string sigPath = exePath + ".sig";
    std::string bakPath = exePath + ".sig.bak";

    if (GetFileAttributesA(bakPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::ifstream isig(sigPath, std::ios::binary);
        if (isig.good()) {
            std::vector<BYTE> orig((std::istreambuf_iterator<char>(isig)), std::istreambuf_iterator<char>());
            isig.close();
            std::ofstream osig(bakPath, std::ios::binary);
            osig.write((const char*)orig.data(), (std::streamsize)orig.size());
        }
    }

    std::ofstream ofs(sigPath, std::ios::binary);
    ofs.write((const char*)sig.data(), (std::streamsize)sig.size());
    ofs.close();
    return true;
}

static int ResignExecutables(const std::string& dir, const std::vector<BYTE>& privBlob)
{
    static const char* kTargets[] = { "SandMan.exe", "SbieCtrl.exe", "SbieSvc.exe", "Start.exe" };
    int n = 0;
    for (auto* t : kTargets) {
        std::string exe = dir + "\\" + t;
        if (GetFileAttributesA(exe.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        if (SignFile(exe, privBlob)) {
            Log("[+]     已重签: %s.sig", t);
            n++;
        }
    }
    return n;
}

// 从 SbieDrv 服务路径推断安装目录，失败则用默认路径
static std::string GetInstallDir()
{
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, "SbieDrv", SERVICE_QUERY_CONFIG);
        if (hSvc) {
            DWORD need = 0;
            QueryServiceConfigA(hSvc, NULL, 0, &need);
            std::vector<BYTE> buf(need > 0 ? need : 4096);
            LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)buf.data();
            if (QueryServiceConfigA(hSvc, cfg, (DWORD)buf.size(), &need) && cfg->lpBinaryPathName) {
                std::string p = cfg->lpBinaryPathName;
                if (p.rfind("\\??\\", 0) == 0) p = p.substr(4);
                size_t slash = p.find_last_of("\\/");
                if (slash != std::string::npos) p = p.substr(0, slash);
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                return p;
            }
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }
    return "C:\\Program Files\\Sandboxie-Plus";
}

// ---------------- 一键流程 ----------------
void RunFlow(const std::string& name, const std::string& level, long long days)
{
    Log("[*] 一键流程: name=\"%s\" level=%s days=%lld", name.c_str(), level.c_str(), days);

    // 1) HWID
    std::string hwid = GetLocalUUID();
    if (hwid.empty()) { Log("[-] 读取本机 SMBIOS UUID 失败"); return; }
    Log("[+] 1/8 本机 HWID: %s", hwid.c_str());

    // 2) 密钥对
    std::vector<BYTE> priv, pub;
    try { GenerateKeyPair(priv, pub); }
    catch (const std::exception& e) { Log("[-] 2/8 密钥生成失败: %s", e.what()); return; }
    Log("[+] 2/8 已生成 ECDSA P-256 密钥对");

    // 3) 证书
    std::string certText = BuildCertificate(name, level, days, hwid, priv, true);
    { std::ofstream ofs("Certificate.dat", std::ios::binary); ofs << certText; }
    { std::ofstream ofs("key.hex");  ofs << Hex(priv) << "\n"; }
    { std::ofstream ofs("mypub.hex"); ofs << Hex(pub) << "\n"; }
    Log("[+] 3/8 已生成 Certificate.dat / key.hex / mypub.hex");
    Log("    公钥: %s", Hex(pub).c_str());

    // 4) 打开驱动
    astra::Astra drv;
    if (!OpenAstra(drv)) {
        Log("[-] 4/8 无法打开 Astra64 驱动，补丁跳过（证书已生成，可稍后手动补丁）");
        return;
    }
    Log("[+] 4/8 Astra64 驱动已打开");

    // 5) 定位
    uint64_t baseVa = GetDriverBase("SbieDrv.sys");
    if (!baseVa) { Log("[-] 5/8 未找到 SbieDrv.sys，补丁跳过"); return; }
    Log("[+] 5/8 SbieDrv.sys 基址 VA: 0x%llX", (unsigned long long)baseVa);
    uint64_t cr3 = FindKernelCr3(drv, baseVa);
    if (!cr3) { Log("[-] 5/8 未找到内核 CR3"); return; }
    Log("[+]     CR3 (PML4) = 0x%llX", (unsigned long long)cr3);
    uint64_t imageSize = 0;
    if (!GetImageSize(drv, cr3, baseVa, imageSize)) { Log("[-] 5/8 读取驱动映像大小失败"); return; }
    uint64_t keyVa = 0, keyPa = 0;
    if (!ScanImageForSig(drv, cr3, baseVa, imageSize, keyVa, keyPa)) { Log("[-] 5/8 映像中未找到 ECS1 公钥"); return; }
    Log("[+]     公钥 VA=0x%llX PA=0x%llX", (unsigned long long)keyVa, (unsigned long long)keyPa);

    // 6) 备份 + 写入 + 读回校验
    BYTE orig[72] = { 0 };
    try { drv.read_phys(keyPa, orig, 72); }
    catch (const std::exception& e) { Log("[-] 6/8 读取原公钥失败: %s", e.what()); return; }
    if (GetFileAttributesA("sbie_key_backup.bin") == INVALID_FILE_ATTRIBUTES) {
        if (SaveRawFile("sbie_key_backup.bin", orig, 72)) Log("[+] 6/8 原公钥已备份到 sbie_key_backup.bin");
        else Log("[-] 6/8 备份写入失败");
    } else {
        Log("[.] 6/8 备份文件已存在，跳过覆盖");
    }

    try { drv.write_phys(keyPa, pub.data(), 72); }
    catch (const std::exception& e) { Log("[-] 6/8 写入失败: %s", e.what()); return; }
    BYTE chk[72] = { 0 };
    try { drv.read_phys(keyPa, chk, 72); } catch (...) {}
    if (memcmp(chk, pub.data(), 72) != 0) {
        Log("[-] 6/8 读回校验失败，自动还原...");
        try { drv.write_phys(keyPa, orig, 72); } catch (...) {}
        return;
    }
    Log("[+] 6/8 新公钥已写入并读回校验通过");

    // 7) 重签 exe
    std::string installDir = GetInstallDir();
    if (GetFileAttributesA(installDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log("[-] 7/8 未找到安装目录 %s，跳过重签", installDir.c_str());
    } else {
        int n = ResignExecutables(installDir, priv);
        Log("[+] 7/8 已重签 %d 个可执行文件（原 .sig 备份为 *.sig.bak）", n);
    }

    // 8) 完成
    Log("");
    Log("[+] 8/8 全部完成！");
    Log("    证书: Certificate.dat（节点锁定 %s）", hwid.c_str());
    Log("    安装目录: %s", installDir.c_str());
    Log("    将 Certificate.dat 放入安装目录后重启 Sandboxie-Plus");
    Log("    注意: 内存补丁重启系统后失效；届时 *.sig.bak 需拷回还原");
}

// ---------------- 还原 ----------------
void RunRestore()
{
    Log("[*] 开始还原...");
    std::string installDir = GetInstallDir();
    static const char* kTargets[] = { "SandMan.exe", "SbieCtrl.exe", "SbieSvc.exe", "Start.exe" };
    for (auto* t : kTargets) {
        std::string bak = installDir + "\\" + t + ".sig.bak";
        std::string sig = installDir + "\\" + t + ".sig";
        if (GetFileAttributesA(bak.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        std::ifstream ib(bak, std::ios::binary);
        if (ib.good()) {
            std::vector<BYTE> data((std::istreambuf_iterator<char>(ib)), std::istreambuf_iterator<char>());
            ib.close();
            std::ofstream os(sig, std::ios::binary);
            os.write((const char*)data.data(), (std::streamsize)data.size());
            os.close();
            Log("[+] 已还原 %s.sig", t);
        }
    }
    std::string certIn = installDir + "\\Certificate.dat";
    if (GetFileAttributesA(certIn.c_str()) != INVALID_FILE_ATTRIBUTES) {
        DeleteFileA(certIn.c_str());
        Log("[+] 已移除安装目录的 Certificate.dat");
    }
    if (GetFileAttributesA("Certificate.dat") != INVALID_FILE_ATTRIBUTES) {
        DeleteFileA("Certificate.dat");
        Log("[+] 已移除当前目录的 Certificate.dat");
    }
    Log("[*] 还原完成。若驱动内存补丁仍在，请重启系统以彻底恢复原公钥。");
}

} // namespace va2pa
