// dllmain.cpp : Defines the entry point for the DLL Application.
#include "pch.h"
#include "ProxyXInput.h"
#include "Hook.h"
#include "PatternScanner.h"
#include "SystemLanguageDetector.h"
#include <iostream>
#include <fstream>
#include <string>

// ============================================
// 日志配置
// ============================================

// Debug模式启用日志，Release模式禁用日志
#ifdef _DEBUG
    #define ENABLE_LOGGING 1
#else
    #define ENABLE_LOGGING 0
#endif

// 日志文件路径
#define LOG_FILE_PATH "advhd_hook.log"

// 是否已初始化日志（用于首次覆盖）
static bool g_logInitialized = false;

// 全局变量
static HookEngine::HookInfo* g_targetFunctionHook = nullptr;

// 日志函数
void WriteLog(const char* message)
{
#if ENABLE_LOGGING
    // 首次写入时覆盖文件，后续追加
    std::ios_base::openmode mode = g_logInitialized ? std::ios::app : std::ios::trunc;
    
    std::ofstream logFile(LOG_FILE_PATH, mode);
    if (logFile.is_open())
    {
        logFile << message << std::endl;
        logFile.close();
        
        // 标记日志已初始化
        if (!g_logInitialized)
            g_logInitialized = true;
    }
#endif
}

// UTF-16日志函数（支持宽字符）
void WriteLogW(const wchar_t* message)
{
#if ENABLE_LOGGING
    // 首次写入时覆盖文件，后续追加
    std::ios_base::openmode mode = g_logInitialized ? std::ios::app : std::ios::trunc;
    
    std::wofstream logFile(LOG_FILE_PATH, mode);
    if (logFile.is_open())
    {
        // 设置UTF-8编码输出
        logFile.imbue(std::locale(""));
        logFile << message << std::endl;
        logFile.close();
        
        // 标记日志已初始化
        if (!g_logInitialized)
            g_logInitialized = true;
    }
#endif
}

// 安全读取UTF-16字符串
std::wstring SafeReadUTF16String(void* ptr, size_t maxLength = 1024)
{
    if (!ptr)
        return L"<NULL>";
    
    // 检查内存是否可读
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
        return L"<INVALID_MEMORY>";
    
    // 检查内存保护属性
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        return L"<PROTECTED_MEMORY>";
    
    // 使用IsBadReadPtr进行额外检查（虽然已弃用，但仍可用于检测）
    if (IsBadReadPtr(ptr, sizeof(wchar_t)))
        return L"<BAD_POINTER>";
    
    // 使用结构化异常处理读取字符串
    wchar_t* wstr = (wchar_t*)ptr;
    std::wstring result;
    
    // 使用SEH保护，但分离到单独的函数
    for (size_t i = 0; i < maxLength; i++)
    {
        // 每次读取前检查是否可读
        if (IsBadReadPtr(&wstr[i], sizeof(wchar_t)))
            break;
        
        wchar_t ch = wstr[i];
        if (ch == L'\0')
            break;
        
        result += ch;
    }
    
    if (result.empty())
        return L"<EMPTY_STRING>";
    
    return result;
}

// 将UTF-16转换为UTF-8用于日志（ASCII兼容）
std::string UTF16ToUTF8(const std::wstring& wstr)
{
    if (wstr.empty())
        return "";
    
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0)
        return "";
    
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], sizeNeeded, nullptr, nullptr);
    
    return result;
}

// ============================================
// 目标函数Hook - 通过签名查找
// 签名: \x40\x53\x55\x56\x57\x48\x83\xEC\x00\x0F\x57\xC0
// 掩码: xxxxxxxx?xxx
// ============================================

// 定义目标函数类型
// 根据你的实际函数签名调整参数类型
// 这里假设是一个典型的x64函数: RCX, RDX, R8, R9, 然后是栈参数
typedef int64_t (*TargetFunction_t)(void* rcx_param, void* rdx_param, void* r8_param, void* r9_param);

// 原始函数指针
static TargetFunction_t Original_TargetFunction = nullptr;

// 前向声明
bool PatchSerialCheck();
void RestoreSerialCheck();

// Hook处理函数
int64_t Hooked_TargetFunction(void* rcx_param, void* rdx_param, void* r8_param, void* r9_param)
{
    // 记录Hook被触发
    char logMsg[2048];
    sprintf_s(logMsg, "Target function hooked! RCX=%p, RDX=%p, R8=%p, R9=%p", 
        rcx_param, rdx_param, r8_param, r9_param);
    WriteLog(logMsg);
    
    // ============================================
    // 读取RDX指向的UTF-16文本
    // ============================================
    
    // 用于存储替换后的字体名
    static std::wstring replacedFontName;
    void* modified_rdx_param = rdx_param;
    
    if (rdx_param != nullptr)
    {
        WriteLog("Reading UTF-16 string from RDX...");
        
        // 读取UTF-16字符串
        std::wstring utf16Text = SafeReadUTF16String(rdx_param);
        
        // 转换为UTF-8并打印
        std::string utf8Text = UTF16ToUTF8(utf16Text);
        
        // 记录UTF-16文本（十六进制地址 + 文本内容）
        sprintf_s(logMsg, "RDX points to UTF-16 string at %p:", rdx_param);
        WriteLog(logMsg);
        
        // 打印UTF-8版本（ASCII兼容日志）
        sprintf_s(logMsg, "  UTF-8: %s", utf8Text.c_str());
        WriteLog(logMsg);
        
        // 打印UTF-16十六进制表示（前32个字符）
        if (utf16Text.length() > 0 && utf16Text[0] != L'<')
        {
            std::string hexDump = "  UTF-16 (Hex): ";
            size_t dumpLen = min(utf16Text.length(), (size_t)32);
            
            for (size_t i = 0; i < dumpLen; i++)
            {
                char hexBuf[16];
                sprintf_s(hexBuf, "%04X ", (unsigned short)utf16Text[i]);
                hexDump += hexBuf;
            }
            
            if (utf16Text.length() > 32)
                hexDump += "...";
            
            WriteLog(hexDump.c_str());
        }
        
        // 打印字符串长度
        sprintf_s(logMsg, "  String length: %zu characters", utf16Text.length());
        WriteLog(logMsg);
        
        // ============================================
        // 字体名称替换逻辑
        // ============================================
        
        // 检查是否为 "BIZ UDゴシック"
        if (utf16Text == L"BIZ UDゴシック")
        {
            // 替换为 "BIZ UDGothic"
            replacedFontName = L"BIZ UDGothic";
            modified_rdx_param = (void*)replacedFontName.c_str();
            
            WriteLog(">>> FONT NAME REPLACED <<<");
            sprintf_s(logMsg, "  Original: %s", utf8Text.c_str());
            WriteLog(logMsg);
            WriteLog("  Replaced: BIZ UDGothic");
            
            sprintf_s(logMsg, "  New RDX pointer: %p", modified_rdx_param);
            WriteLog(logMsg);
        }
    }
    else
    {
        WriteLog("RDX is NULL - no string to read");
    }
    
    WriteLog("----------------------------------------");
    
    // 调用原始函数（使用可能修改过的RDX）
    if (Original_TargetFunction)
    {
        return Original_TargetFunction(rcx_param, modified_rdx_param, r8_param, r9_param);
    }
    
    return 0;
}

// 初始化Hook
void InitializeHooks()
{
    WriteLog("Initializing hooks...");
    
    // ============================================
    // Patch序列号检查（所有系统都执行，不考虑语言）
    // ============================================
    WriteLog("============================================");
    WriteLog("Attempting to patch serial check...");
    
    if (PatchSerialCheck())
    {
        WriteLog("Serial check patched successfully!");
    }
    else
    {
        WriteLog("Failed to patch serial check (signature not found or patch failed)");
        WriteLog("Game will continue with original serial check.");
    }
    
    WriteLog("============================================");
    
    // ============================================
    // 检查系统语言环境
    // ============================================
    WriteLog("Checking system language...");
    
    // 获取系统语言信息
    auto systemLang = SystemLanguageDetector::GetSystemLanguage();
    auto uiLang = SystemLanguageDetector::GetSystemUILanguage();
    auto userLang = SystemLanguageDetector::GetUserDefaultLanguage();
    
    char langMsg[512];
    sprintf_s(langMsg, "System Language: %s, UI Language: %s, User Language: %s",
        SystemLanguageDetector::GetLanguageName(systemLang),
        SystemLanguageDetector::GetLanguageName(uiLang),
        SystemLanguageDetector::GetLanguageName(userLang));
    WriteLog(langMsg);
    
    // 检查是否为日语环境
    if (SystemLanguageDetector::IsJapaneseSystem())
    {
        WriteLog("============================================");
        WriteLog("JAPANESE SYSTEM DETECTED!");
        WriteLog("Hook installation SKIPPED as per configuration.");
        WriteLog("============================================");
        return; // 直接返回，不安装Hook
    }
    
    WriteLog("Non-Japanese system detected. Proceeding with hook installation...");
    
    // ============================================
    // 通过签名查找并Hook目标函数
    // ============================================
    
    // 定义要查找的签名
    const char* pattern = "\x40\x53\x55\x56\x57\x48\x83\xEC\x00\x0F\x57\xC0";
    const char* mask    = "xxxxxxxx?xxx";
    
    WriteLog("Searching for target function with signature...");
    
    // 在主模块中查找签名 (nullptr表示主EXE)
    void* targetAddress = PatternScanner::FindPattern(nullptr, pattern, mask);
    
    if (targetAddress)
    {
        char logMsg[256];
        sprintf_s(logMsg, "Found target function at address: 0x%p", targetAddress);
        WriteLog(logMsg);
        
        // 安装Hook
        g_targetFunctionHook = HookEngine::InstallHook(targetAddress, (void*)Hooked_TargetFunction);
        
        if (g_targetFunctionHook)
        {
            // 保存原始函数指针
            Original_TargetFunction = (TargetFunction_t)g_targetFunctionHook->originalFunction;
            
            WriteLog("Hook installed successfully!");
        }
        else
        {
            WriteLog("ERROR: Failed to install hook!");
        }
    }
    else
    {
        WriteLog("ERROR: Target function signature not found!");
        WriteLog("Please verify the signature is correct:");
        WriteLog("Pattern: \\x40\\x53\\x55\\x56\\x57\\x48\\x83\\xEC\\x00\\x0F\\x57\\xC0");
        WriteLog("Mask:    xxxxxxxx?xxx");
    }
    
    WriteLog("Hook initialization complete.");
}

// ============================================
// 序列号检查Patch - NOP掉跳转指令
// 签名: \x48\x8D\x4D\x00\xE8\x00\x00\x00\x00\x48\x8B\xD0\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xC8\xFF\x15\x00\x00\x00\x00\x48\x8D\x4D\x00\x48\x85\xC0\x0F\x84\x00\x00\x00\x00
// 掩码: xxx?x????xxxxxx????x????xxxxx????xxx?xxxxx????
// 目标: NOP掉最后的 je 指令 (0F 84 -> 90 90 90 90 90 90)
// ============================================

// 保存原始字节用于恢复
static uint8_t g_originalSerialCheckBytes[6] = {0};
static void* g_serialCheckAddress = nullptr;

// Patch序列号检查
bool PatchSerialCheck()
{
    WriteLog("Searching for serial check with signature...");
    
    // 定义签名
    const char* pattern = "\x48\x8D\x4D\x00\xE8\x00\x00\x00\x00\x48\x8B\xD0\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xC8\xFF\x15\x00\x00\x00\x00\x48\x8D\x4D\x00\x48\x85\xC0\x0F\x84\x00\x00\x00\x00";
    const char* mask    = "xxx?x????xxxxxx????x????xxxxx????xxx?xxxxx????";
    
    // 在主模块中查找签名
    void* baseAddress = PatternScanner::FindPattern(nullptr, pattern, mask);
    
    if (!baseAddress)
    {
        WriteLog("ERROR: Serial check signature not found!");
        return false;
    }
    
    char logMsg[256];
    sprintf_s(logMsg, "Found serial check at address: 0x%p", baseAddress);
    WriteLog(logMsg);
    
    // 计算 je 指令的位置 (签名中 0F 84 的偏移是40字节)
    // 签名结构: 4+5+3+7+5+3+6+4+3+6 = 46字节，0F 84在第40字节
    uint8_t* jeAddress = (uint8_t*)baseAddress + 40;
    g_serialCheckAddress = jeAddress;
    
    sprintf_s(logMsg, "Target je instruction at: 0x%p", jeAddress);
    WriteLog(logMsg);
    
    // 验证是否为 je 指令 (0F 84)
    if (jeAddress[0] != 0x0F || jeAddress[1] != 0x84)
    {
        WriteLog("ERROR: Expected 'je' instruction (0F 84) not found at calculated offset!");
        sprintf_s(logMsg, "Found bytes: %02X %02X instead of 0F 84", jeAddress[0], jeAddress[1]);
        WriteLog(logMsg);
        return false;
    }
    
    WriteLog("Verified: Found 'je' instruction (0F 84)");
    
    // 保存原始字节
    memcpy(g_originalSerialCheckBytes, jeAddress, 6);
    sprintf_s(logMsg, "Original bytes: %02X %02X %02X %02X %02X %02X",
        g_originalSerialCheckBytes[0], g_originalSerialCheckBytes[1],
        g_originalSerialCheckBytes[2], g_originalSerialCheckBytes[3],
        g_originalSerialCheckBytes[4], g_originalSerialCheckBytes[5]);
    WriteLog(logMsg);
    
    // 修改内存保护
    DWORD oldProtect;
    if (!VirtualProtect(jeAddress, 6, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        WriteLog("ERROR: Failed to change memory protection!");
        return false;
    }
    
    // 用NOP替换 je 指令 (6字节: 0F 84 xx xx xx xx -> 90 90 90 90 90 90)
    memset(jeAddress, 0x90, 6);
    
    // 恢复内存保护
    VirtualProtect(jeAddress, 6, oldProtect, &oldProtect);
    
    // 刷新指令缓存
    FlushInstructionCache(GetCurrentProcess(), jeAddress, 6);
    
    WriteLog(">>> SERIAL CHECK PATCHED <<<");
    WriteLog("  Replaced: 0F 84 xx xx xx xx (je)");
    WriteLog("  With:     90 90 90 90 90 90 (nop)");
    WriteLog("  Effect:   Serial check bypassed!");
    
    return true;
}

// 恢复序列号检查Patch
void RestoreSerialCheck()
{
    if (!g_serialCheckAddress)
        return;
    
    WriteLog("Restoring serial check...");
    
    // 修改内存保护
    DWORD oldProtect;
    if (VirtualProtect(g_serialCheckAddress, 6, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        // 恢复原始字节
        memcpy(g_serialCheckAddress, g_originalSerialCheckBytes, 6);
        
        // 恢复内存保护
        VirtualProtect(g_serialCheckAddress, 6, oldProtect, &oldProtect);
        
        // 刷新指令缓存
        FlushInstructionCache(GetCurrentProcess(), g_serialCheckAddress, 6);
        
        WriteLog("Serial check restored.");
    }
    
    g_serialCheckAddress = nullptr;
}

// 清理Hook系统
void CleanupHooks()
{
    WriteLog("Cleaning up hooks...");
    
    // 恢复序列号检查Patch
    RestoreSerialCheck();
    
    if (g_targetFunctionHook)
    {
        HookEngine::UninstallHook(g_targetFunctionHook);
        g_targetFunctionHook = nullptr;
        WriteLog("Target function hook removed.");
    }
    
    WriteLog("Hook cleanup complete.");
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // 禁用线程通知以提高性能
        DisableThreadLibraryCalls(hModule);
        
        WriteLog("============================================");
        WriteLog("advhd_hook DLL loaded - XINPUT1_4.dll Hijack Version");
        WriteLog("============================================");
        
        // 初始化代理 - 加载原始xinput1_4.dll
        if (!InitializeProxy())
        {
            WriteLog("Failed to initialize XInput proxy!");
            return FALSE;
        }
        WriteLog("XInput proxy initialized successfully.");
        
        // 初始化Hook系统（包含语言检测）
        InitializeHooks();
        
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        WriteLog("advhd_hook DLL unloading...");
        
        // 清理Hook
        CleanupHooks();
        
        // 清理代理
        CleanupProxy();
        
        WriteLog("advhd_hook DLL unloaded.");
        WriteLog("============================================");
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

