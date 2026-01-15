#pragma once
#include <Windows.h>

// 系统语言环境检测器
class SystemLanguageDetector
{
public:
    // 语言代码枚举
    enum class LanguageCode
    {
        Unknown,
        Japanese,       // 日语
        Chinese,        // 中文
        English,        // 英语
        Korean,         // 韩语
        // 可以根据需要添加更多语言
    };

    // 获取当前系统语言
    static LanguageCode GetSystemLanguage();

    // 获取系统UI语言
    static LanguageCode GetSystemUILanguage();

    // 获取用户区域设置语言
    static LanguageCode GetUserDefaultLanguage();

    // 检查是否为日语环境
    static bool IsJapaneseSystem();

    // 获取语言名称（用于日志）
    static const char* GetLanguageName(LanguageCode code);

    // 获取当前语言的LCID（区域设置ID）
    static LCID GetSystemLCID();

private:
    // LANGID转换为LanguageCode
    static LanguageCode ConvertLangIDToLanguageCode(LANGID langId);
};

// 便捷宏
#define IS_JAPANESE_SYSTEM() SystemLanguageDetector::IsJapaneseSystem()
