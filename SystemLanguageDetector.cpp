#include "pch.h"
#include "SystemLanguageDetector.h"

// 将LANGID转换为LanguageCode
SystemLanguageDetector::LanguageCode SystemLanguageDetector::ConvertLangIDToLanguageCode(LANGID langId)
{
    // 获取主语言ID（忽略子语言）
    WORD primaryLang = PRIMARYLANGID(langId);

    switch (primaryLang)
    {
    case LANG_JAPANESE:
        return LanguageCode::Japanese;
    case LANG_CHINESE:
        return LanguageCode::Chinese;
    case LANG_ENGLISH:
        return LanguageCode::English;
    case LANG_KOREAN:
        return LanguageCode::Korean;
    default:
        return LanguageCode::Unknown;
    }
}

// 获取当前系统语言
SystemLanguageDetector::LanguageCode SystemLanguageDetector::GetSystemLanguage()
{
    LANGID langId = GetSystemDefaultLangID();
    return ConvertLangIDToLanguageCode(langId);
}

// 获取系统UI语言
SystemLanguageDetector::LanguageCode SystemLanguageDetector::GetSystemUILanguage()
{
    LANGID langId = GetSystemDefaultUILanguage();
    return ConvertLangIDToLanguageCode(langId);
}

// 获取用户区域设置语言
SystemLanguageDetector::LanguageCode SystemLanguageDetector::GetUserDefaultLanguage()
{
    LANGID langId = GetUserDefaultLangID();
    return ConvertLangIDToLanguageCode(langId);
}

// 检查是否为日语环境
bool SystemLanguageDetector::IsJapaneseSystem()
{
    // 检查系统默认语言
    if (GetSystemLanguage() == LanguageCode::Japanese)
        return true;

    // 检查系统UI语言
    if (GetSystemUILanguage() == LanguageCode::Japanese)
        return true;

    // 检查用户区域设置
    if (GetUserDefaultLanguage() == LanguageCode::Japanese)
        return true;

    return false;
}

// 获取语言名称（用于日志）
const char* SystemLanguageDetector::GetLanguageName(LanguageCode code)
{
    switch (code)
    {
    case LanguageCode::Japanese:
        return "Japanese";
    case LanguageCode::Chinese:
        return "Chinese";
    case LanguageCode::English:
        return "English";
    case LanguageCode::Korean:
        return "Korean";
    case LanguageCode::Unknown:
    default:
        return "Unknown";
    }
}

// 获取当前语言的LCID
LCID SystemLanguageDetector::GetSystemLCID()
{
    return GetSystemDefaultLCID();
}
