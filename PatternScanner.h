#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <cstdint>

// 模式扫描器 - 用于在内存中查找字节特征
class PatternScanner
{
public:
    // 在指定模块中查找模式
    // moduleName: 模块名称 (如 "game.exe", nullptr表示主模块)
    // pattern: 字节模式
    // mask: 掩码 ("x"表示匹配, "?"表示通配符)
    // offset: 从找到的地址偏移多少字节 (默认0)
    // occurrence: 第几个匹配项 (默认第1个, 从1开始)
    static void* FindPattern(const char* moduleName, const char* pattern, const char* mask, int offset = 0, int occurrence = 1);
    
    // 在指定地址范围内查找模式
    static void* FindPatternInRange(uint8_t* start, size_t size, const char* pattern, const char* mask, int occurrence = 1);
    
    // 查找所有匹配的地址
    static std::vector<void*> FindAllPatterns(const char* moduleName, const char* pattern, const char* mask);
    
    // 辅助函数: 将十六进制字符串转换为字节数组和掩码
    // 例如: "48 89 5C 24 ?? 57" -> pattern + mask
    static bool ParsePatternString(const char* patternStr, std::vector<uint8_t>& outPattern, std::string& outMask);

private:
    // 获取模块信息
    static bool GetModuleInfo(const char* moduleName, MODULEINFO& outInfo);
    
    // 比较字节序列
    static bool CompareBytes(const uint8_t* data, const char* pattern, const char* mask, size_t length);
};

// 便捷宏定义
#define FIND_PATTERN(module, pattern, mask) PatternScanner::FindPattern(module, pattern, mask, 0, 1)
#define FIND_PATTERN_OFFSET(module, pattern, mask, offset) PatternScanner::FindPattern(module, pattern, mask, offset, 1)
