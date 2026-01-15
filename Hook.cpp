#include "pch.h"
#include "Hook.h"
#include <vector>

// 全局Hook列表
static std::vector<HookEngine::HookInfo*> g_hooks;

// 修改内存保护
bool HookEngine::ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect)
{
    return VirtualProtect(address, size, newProtect, oldProtect) != 0;
}

// 简单的指令长度计算 (支持常见的x86/x64指令)
size_t HookEngine::GetInstructionLength(void* address, size_t minLength)
{
    uint8_t* code = (uint8_t*)address;
    size_t length = 0;

#ifdef _WIN64
    // x64: 需要至少14字节用于绝对跳转 (mov rax, addr; jmp rax)
    while (length < minLength)
    {
        uint8_t opcode = code[length];

        // REX 前缀
        if (opcode >= 0x40 && opcode <= 0x4F)
        {
            length++;
            opcode = code[length];
        }

        // 常见指令长度判断
        if (opcode == 0x50 || opcode == 0x51 || opcode == 0x52 || opcode == 0x53 ||
            opcode == 0x54 || opcode == 0x55 || opcode == 0x56 || opcode == 0x57) // push reg
        {
            length += 1;
        }
        else if (opcode == 0x58 || opcode == 0x59 || opcode == 0x5A || opcode == 0x5B ||
            opcode == 0x5C || opcode == 0x5D || opcode == 0x5E || opcode == 0x5F) // pop reg
        {
            length += 1;
        }
        else if (opcode == 0x90) // nop
        {
            length += 1;
        }
        else if (opcode == 0xC3) // ret
        {
            length += 1;
        }
        else if (opcode == 0x48 || opcode == 0x4C) // REX.W prefix common in x64
        {
            length += 1;
            if (length < minLength)
            {
                uint8_t nextOp = code[length];
                if (nextOp == 0x8B || nextOp == 0x89) // mov
                {
                    length += 2; // ModR/M byte
                }
                else if (nextOp == 0x83 || nextOp == 0x81) // add/sub/cmp
                {
                    length += 3;
                }
                else
                {
                    length += 2;
                }
            }
        }
        else if (opcode == 0x8B || opcode == 0x89) // mov r, r/m or mov r/m, r
        {
            length += 2;
        }
        else if (opcode == 0xE8 || opcode == 0xE9) // call/jmp rel32
        {
            length += 5;
        }
        else if (opcode == 0xFF) // indirect call/jmp
        {
            length += 2;
        }
        else
        {
            // 默认假设为2字节指令
            length += 2;
        }
    }
#else
    // x86: 需要至少5字节用于相对跳转
    while (length < minLength)
    {
        uint8_t opcode = code[length];

        if (opcode == 0x55) // push ebp
        {
            length += 1;
        }
        else if (opcode == 0x8B) // mov
        {
            length += 2;
        }
        else if (opcode == 0x89) // mov
        {
            length += 2;
        }
        else if (opcode == 0xE8 || opcode == 0xE9) // call/jmp rel32
        {
            length += 5;
        }
        else if (opcode == 0x50 || opcode == 0x51 || opcode == 0x52 || opcode == 0x53 ||
            opcode == 0x54 || opcode == 0x56 || opcode == 0x57) // push reg
        {
            length += 1;
        }
        else
        {
            length += 1;
        }
    }
#endif

    return length;
}

// 创建trampoline
void* HookEngine::CreateTrampoline(void* targetAddress, size_t hookLength)
{
    // 分配可执行内存
    void* trampoline = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline)
        return nullptr;

    uint8_t* trampolineCode = (uint8_t*)trampoline;
    uint8_t* originalCode = (uint8_t*)targetAddress;

    // 复制原始字节到trampoline
    memcpy(trampolineCode, originalCode, hookLength);

    // 添加跳转回原函数
#ifdef _WIN64
    // jmp [rip+0]; 后面跟着64位地址
    uint8_t* jumpBack = trampolineCode + hookLength;
    jumpBack[0] = 0xFF;
    jumpBack[1] = 0x25;
    *(DWORD*)(jumpBack + 2) = 0; // RIP相对偏移为0
    *(uint64_t*)(jumpBack + 6) = (uint64_t)originalCode + hookLength;
#else
    // jmp absolute
    uint8_t* jumpBack = trampolineCode + hookLength;
    jumpBack[0] = 0xE9; // jmp rel32
    *(DWORD*)(jumpBack + 1) = (DWORD)((uint8_t*)targetAddress + hookLength - (jumpBack + 5));
#endif

    return trampoline;
}

// 安装Hook
HookEngine::HookInfo* HookEngine::InstallHook(void* targetAddress, void* hookFunction)
{
    if (!targetAddress || !hookFunction)
        return nullptr;

    // 创建HookInfo
    HookInfo* info = new HookInfo();
    info->targetAddress = targetAddress;
    info->hookFunction = hookFunction;
    info->isHooked = false;

#ifdef _WIN64
    // x64需要14字节: mov rax, addr(10) + jmp rax(2)
    size_t hookLength = GetInstructionLength(targetAddress, 14);
#else
    // x86需要5字节: jmp rel32
    size_t hookLength = GetInstructionLength(targetAddress, 5);
#endif

    info->originalLength = hookLength;

    // 保存原始字节
    memcpy(info->originalBytes, targetAddress, hookLength);

    // 创建trampoline
    info->originalFunction = CreateTrampoline(targetAddress, hookLength);
    if (!info->originalFunction)
    {
        delete info;
        return nullptr;
    }

    // 修改内存保护
    DWORD oldProtect;
    if (!ChangeMemoryProtection(targetAddress, hookLength, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        VirtualFree(info->originalFunction, 0, MEM_RELEASE);
        delete info;
        return nullptr;
    }

    // 写入跳转指令
#ifdef _WIN64
    // mov rax, hookFunction
    // jmp rax
    uint8_t* target = (uint8_t*)targetAddress;
    target[0] = 0x48; // REX.W prefix
    target[1] = 0xB8; // mov rax, imm64
    *(uint64_t*)(target + 2) = (uint64_t)hookFunction;
    target[10] = 0xFF; // jmp rax
    target[11] = 0xE0;

    // 填充剩余字节为NOP
    for (size_t i = 12; i < hookLength; i++)
        target[i] = 0x90;
#else
    // jmp rel32
    uint8_t* target = (uint8_t*)targetAddress;
    target[0] = 0xE9;
    *(DWORD*)(target + 1) = (DWORD)((uint8_t*)hookFunction - target - 5);

    // 填充剩余字节为NOP
    for (size_t i = 5; i < hookLength; i++)
        target[i] = 0x90;
#endif

    // 恢复内存保护
    ChangeMemoryProtection(targetAddress, hookLength, oldProtect, &oldProtect);

    // 刷新指令缓存
    FlushInstructionCache(GetCurrentProcess(), targetAddress, hookLength);

    info->isHooked = true;
    g_hooks.push_back(info);

    return info;
}

// 卸载Hook
bool HookEngine::UninstallHook(HookInfo* hookInfo)
{
    if (!hookInfo || !hookInfo->isHooked)
        return false;

    // 修改内存保护
    DWORD oldProtect;
    if (!ChangeMemoryProtection(hookInfo->targetAddress, hookInfo->originalLength, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    // 恢复原始字节
    memcpy(hookInfo->targetAddress, hookInfo->originalBytes, hookInfo->originalLength);

    // 恢复内存保护
    ChangeMemoryProtection(hookInfo->targetAddress, hookInfo->originalLength, oldProtect, &oldProtect);

    // 刷新指令缓存
    FlushInstructionCache(GetCurrentProcess(), hookInfo->targetAddress, hookInfo->originalLength);

    // 释放trampoline
    if (hookInfo->originalFunction)
        VirtualFree(hookInfo->originalFunction, 0, MEM_RELEASE);

    hookInfo->isHooked = false;

    // 从列表移除
    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it)
    {
        if (*it == hookInfo)
        {
            g_hooks.erase(it);
            break;
        }
    }

    delete hookInfo;
    return true;
}
