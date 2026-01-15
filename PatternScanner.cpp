#include "pch.h"
#include "PatternScanner.h"
#include <sstream>

// 获取模块信息
bool PatternScanner::GetModuleInfo(const char* moduleName, MODULEINFO& outInfo)
{
    HMODULE hModule = nullptr;
    
    if (moduleName == nullptr)
    {
        // 获取主模块
        hModule = GetModuleHandleA(nullptr);
    }
    else
    {
        hModule = GetModuleHandleA(moduleName);
    }
    
    if (!hModule)
        return false;
    
    return GetModuleInformation(GetCurrentProcess(), hModule, &outInfo, sizeof(MODULEINFO)) != 0;
}

// 比较字节序列
bool PatternScanner::CompareBytes(const uint8_t* data, const char* pattern, const char* mask, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        if (mask[i] == 'x' && data[i] != (uint8_t)pattern[i])
            return false;
    }
    return true;
}

// 在指定地址范围内查找模式
void* PatternScanner::FindPatternInRange(uint8_t* start, size_t size, const char* pattern, const char* mask, int occurrence)
{
    size_t patternLength = strlen(mask);
    int foundCount = 0;
    
    for (size_t i = 0; i <= size - patternLength; i++)
    {
        if (CompareBytes(start + i, pattern, mask, patternLength))
        {
            foundCount++;
            if (foundCount == occurrence)
            {
                return start + i;
            }
        }
    }
    
    return nullptr;
}

// 在指定模块中查找模式
void* PatternScanner::FindPattern(const char* moduleName, const char* pattern, const char* mask, int offset, int occurrence)
{
    MODULEINFO modInfo;
    if (!GetModuleInfo(moduleName, modInfo))
        return nullptr;
    
    uint8_t* baseAddress = (uint8_t*)modInfo.lpBaseOfDll;
    size_t moduleSize = modInfo.SizeOfImage;
    
    void* result = FindPatternInRange(baseAddress, moduleSize, pattern, mask, occurrence);
    
    if (result && offset != 0)
    {
        result = (void*)((uintptr_t)result + offset);
    }
    
    return result;
}

// 查找所有匹配的地址
std::vector<void*> PatternScanner::FindAllPatterns(const char* moduleName, const char* pattern, const char* mask)
{
    std::vector<void*> results;
    
    MODULEINFO modInfo;
    if (!GetModuleInfo(moduleName, modInfo))
        return results;
    
    uint8_t* baseAddress = (uint8_t*)modInfo.lpBaseOfDll;
    size_t moduleSize = modInfo.SizeOfImage;
    size_t patternLength = strlen(mask);
    
    for (size_t i = 0; i <= moduleSize - patternLength; i++)
    {
        if (CompareBytes(baseAddress + i, pattern, mask, patternLength))
        {
            results.push_back(baseAddress + i);
        }
    }
    
    return results;
}

// 将十六进制字符串转换为字节数组和掩码
bool PatternScanner::ParsePatternString(const char* patternStr, std::vector<uint8_t>& outPattern, std::string& outMask)
{
    outPattern.clear();
    outMask.clear();
    
    std::istringstream stream(patternStr);
    std::string token;
    
    while (stream >> token)
    {
        if (token == "??" || token == "?")
        {
            outPattern.push_back(0x00);
            outMask.push_back('?');
        }
        else
        {
            try
            {
                uint8_t byte = (uint8_t)std::stoi(token, nullptr, 16);
                outPattern.push_back(byte);
                outMask.push_back('x');
            }
            catch (...)
            {
                return false;
            }
        }
    }
    
    return !outPattern.empty();
}
