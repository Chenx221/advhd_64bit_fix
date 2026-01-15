#pragma once
#include <Windows.h>
#include <cstdint>

// Hook引擎类 - 用于实现inline hook
class HookEngine
{
public:
    // Hook信息结构
    struct HookInfo
    {
        void* targetAddress;      // 目标函数地址
        void* hookFunction;       // Hook函数地址
        void* originalFunction;   // 保存原始函数的trampoline
        uint8_t originalBytes[32]; // 保存原始字节
        size_t originalLength;    // 原始指令长度
        bool isHooked;            // 是否已经hook
    };

    // 安装inline hook
    // targetAddress: 要hook的目标地址
    // hookFunction: hook处理函数地址
    // 返回HookInfo指针,失败返回nullptr
    static HookInfo* InstallHook(void* targetAddress, void* hookFunction);

    // 卸载hook
    static bool UninstallHook(HookInfo* hookInfo);

    // 创建trampoline - 保存原始指令并跳转回原函数
    static void* CreateTrampoline(void* targetAddress, size_t hookLength);

    // 获取指令长度 (简单实现,支持常见x86/x64指令)
    static size_t GetInstructionLength(void* address, size_t minLength);

private:
    // 修改内存保护属性
    static bool ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect);
};

// 用于保存寄存器上下文的结构
#ifdef _WIN64
struct RegisterContext
{
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rflags;
};
#else
struct RegisterContext
{
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
    uint32_t eflags;
};
#endif

// Hook回调函数类型 - 可以在这里修改寄存器
typedef void (*HookCallback)(RegisterContext* context);
