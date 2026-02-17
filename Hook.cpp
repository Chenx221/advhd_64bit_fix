#include "pch.h"
#include "Hook.h"
#include <MinHook.h>
#include <cstring>
#include <vector>

#ifdef _WIN64
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// ȫ��Hook�б�
static std::vector<HookEngine::HookInfo*> g_hooks;
static bool g_minHookInitialized = false;

static bool EnsureMinHookInitialized()
{
    if (g_minHookInitialized)
        return true;

    const MH_STATUS status = MH_Initialize();
    if (status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED)
    {
        g_minHookInitialized = true;
        return true;
    }

    return false;
}

// �޸��ڴ汣��
bool HookEngine::ChangeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD* oldProtect)
{
    return VirtualProtect(address, size, newProtect, oldProtect) != 0;
}

// �򵥵�ָ��ȼ��� (֧�ֳ�����x86/x64ָ��)
size_t HookEngine::GetInstructionLength(void* address, size_t minLength)
{
    (void)address;
    return minLength;
}

// ����trampoline
void* HookEngine::CreateTrampoline(void* targetAddress, size_t hookLength)
{
    (void)targetAddress;
    (void)hookLength;
    return nullptr;
}

// ��װHook
HookEngine::HookInfo* HookEngine::InstallHook(void* targetAddress, void* hookFunction)
{
    if (!targetAddress || !hookFunction)
        return nullptr;

    if (!EnsureMinHookInitialized())
        return nullptr;

    // ����HookInfo
    HookInfo* info = new HookInfo();
    info->targetAddress = targetAddress;
    info->hookFunction = hookFunction;
    info->originalFunction = nullptr;
    info->originalLength = 0;
    memset(info->originalBytes, 0, sizeof(info->originalBytes));
    info->isHooked = false;

    if (MH_CreateHook(targetAddress, hookFunction, &info->originalFunction) != MH_OK)
    {
        delete info;
        return nullptr;
    }

    if (MH_EnableHook(targetAddress) != MH_OK)
    {
        MH_RemoveHook(targetAddress);
        delete info;
        return nullptr;
    }

    info->isHooked = true;
    g_hooks.push_back(info);

    return info;
}

// ж��Hook
bool HookEngine::UninstallHook(HookInfo* hookInfo)
{
    if (!hookInfo || !hookInfo->isHooked)
        return false;

    if (MH_DisableHook(hookInfo->targetAddress) != MH_OK)
        return false;

    if (MH_RemoveHook(hookInfo->targetAddress) != MH_OK)
        return false;

    hookInfo->isHooked = false;

    // ���б��Ƴ�
    for (auto it = g_hooks.begin(); it != g_hooks.end(); ++it)
    {
        if (*it == hookInfo)
        {
            g_hooks.erase(it);
            break;
        }
    }

    delete hookInfo;

    if (g_hooks.empty() && g_minHookInitialized)
    {
        if (MH_Uninitialize() == MH_OK)
            g_minHookInitialized = false;
    }

    return true;
}
