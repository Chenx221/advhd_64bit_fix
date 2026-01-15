// HookConfig.h - Hook配置示例
// 这个文件展示如何配置和管理多个Hook
#pragma once
#include "Hook.h"
#include <vector>

// Hook配置结构
struct HookConfig
{
    const char* name;           // Hook名称
    void* targetAddress;        // 目标地址 (可以是绝对地址或nullptr)
    const char* moduleName;     // 模块名称 (如果按模块+偏移查找)
    uintptr_t offset;          // 偏移地址
    void* hookFunction;         // Hook函数指针
    bool enabled;              // 是否启用
};

// Hook管理器类
class HookManager
{
private:
    std::vector<HookEngine::HookInfo*> hooks;
    
public:
    // 根据配置安装Hook
    bool InstallHookFromConfig(const HookConfig& config)
    {
        void* targetAddr = config.targetAddress;
        
        // 如果没有指定绝对地址,尝试通过模块+偏移计算
        if (!targetAddr && config.moduleName)
        {
            HMODULE module = GetModuleHandleA(config.moduleName);
            if (!module)
                return false;
            
            targetAddr = (void*)((uintptr_t)module + config.offset);
        }
        
        if (!targetAddr || !config.enabled)
            return false;
        
        HookEngine::HookInfo* hookInfo = HookEngine::InstallHook(targetAddr, config.hookFunction);
        if (hookInfo)
        {
            hooks.push_back(hookInfo);
            return true;
        }
        
        return false;
    }
    
    // 卸载所有Hook
    void UninstallAll()
    {
        for (auto hook : hooks)
        {
            HookEngine::UninstallHook(hook);
        }
        hooks.clear();
    }
    
    // 获取已安装的Hook数量
    size_t GetHookCount() const
    {
        return hooks.size();
    }
};

// ============================================
// Hook函数定义示例
// ============================================

// 示例1: Hook一个接受两个int参数的函数
typedef int (WINAPI* IntIntFunc_t)(int, int);
IntIntFunc_t Original_IntIntFunc = nullptr;

int WINAPI Hook_IntIntFunc(int param1, int param2)
{
    // 记录日志
    char log[256];
    sprintf_s(log, "Hook_IntIntFunc: params=(%d, %d)", param1, param2);
    WriteLog(log);
    
    // 修改参数
    param1 = param1 * 2;
    param2 = param2 + 100;
    
    // 调用原始函数
    if (Original_IntIntFunc)
        return Original_IntIntFunc(param1, param2);
    
    return 0;
}

// 示例2: Hook一个接受指针参数的函数
typedef bool (WINAPI* PointerFunc_t)(void*, int);
PointerFunc_t Original_PointerFunc = nullptr;

bool WINAPI Hook_PointerFunc(void* ptr, int size)
{
    WriteLog("Hook_PointerFunc called");
    
    // 可以在这里检查和修改指针指向的数据
    if (ptr && size > 0)
    {
        // 例如: 修改内存数据
        // memset(ptr, 0, size);
    }
    
    if (Original_PointerFunc)
        return Original_PointerFunc(ptr, size);
    
    return false;
}

// 示例3: Hook一个返回值函数
typedef float (WINAPI* GetValueFunc_t)();
GetValueFunc_t Original_GetValueFunc = nullptr;

float WINAPI Hook_GetValueFunc()
{
    float originalValue = 0.0f;
    
    if (Original_GetValueFunc)
        originalValue = Original_GetValueFunc();
    
    // 修改返回值
    float modifiedValue = originalValue * 1.5f;
    
    char log[256];
    sprintf_s(log, "Hook_GetValueFunc: %f -> %f", originalValue, modifiedValue);
    WriteLog(log);
    
    return modifiedValue;
}

// ============================================
// Hook配置表
// ============================================

// 定义所有要Hook的函数配置
// 使用前需要通过逆向工程找到正确的地址或偏移
static HookConfig g_hookConfigs[] = 
{
    // 示例配置 (需要替换为实际地址)
    {
        "IntIntFunc",           // Hook名称
        nullptr,                // 目标地址 (使用模块+偏移时为nullptr)
        "game.exe",            // 模块名称
        0x12345,               // 偏移地址
        (void*)Hook_IntIntFunc, // Hook函数
        false                   // 是否启用 (改为true启用)
    },
    {
        "PointerFunc",
        (void*)0x00401000,     // 直接使用绝对地址
        nullptr,
        0,
        (void*)Hook_PointerFunc,
        false
    },
    {
        "GetValueFunc",
        nullptr,
        "engine.dll",
        0x56789,
        (void*)Hook_GetValueFunc,
        false
    }
};

// ============================================
// 初始化函数
// ============================================

extern void WriteLog(const char* message); // 声明日志函数

inline HookManager* InitializeHooksFromConfig()
{
    static HookManager manager;
    
    WriteLog("Installing hooks from configuration...");
    
    int successCount = 0;
    int totalCount = sizeof(g_hookConfigs) / sizeof(HookConfig);
    
    for (int i = 0; i < totalCount; i++)
    {
        const HookConfig& config = g_hookConfigs[i];
        
        if (manager.InstallHookFromConfig(config))
        {
            char log[256];
            sprintf_s(log, "Hook installed: %s", config.name);
            WriteLog(log);
            successCount++;
        }
        else if (config.enabled)
        {
            char log[256];
            sprintf_s(log, "Failed to install hook: %s", config.name);
            WriteLog(log);
        }
    }
    
    char log[256];
    sprintf_s(log, "Hooks installed: %d/%d", successCount, totalCount);
    WriteLog(log);
    
    return &manager;
}
