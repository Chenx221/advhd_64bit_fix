#include "pch.h"
#include "ProxyXInput.h"
#include <string>

// 原始DLL句柄
static HMODULE g_originalDLL = nullptr;

// XInput函数指针类型定义
typedef DWORD (WINAPI* XInputGetState_t)(DWORD, void*);
typedef DWORD (WINAPI* XInputSetState_t)(DWORD, void*);
typedef DWORD (WINAPI* XInputGetCapabilities_t)(DWORD, DWORD, void*);
typedef void (WINAPI* XInputEnable_t)(BOOL);
typedef DWORD (WINAPI* XInputGetDSoundAudioDeviceGuids_t)(DWORD, void*, void*);
typedef DWORD (WINAPI* XInputGetBatteryInformation_t)(DWORD, BYTE, void*);
typedef DWORD (WINAPI* XInputGetKeystroke_t)(DWORD, DWORD, void*);
typedef DWORD (WINAPI* XInputGetStateEx_t)(DWORD, void*);
typedef DWORD (WINAPI* XInputWaitForGuideButton_t)(DWORD, DWORD, void*);
typedef DWORD (WINAPI* XInputCancelGuideButtonWait_t)(DWORD);
typedef DWORD (WINAPI* XInputPowerOffController_t)(DWORD);

// 函数指针
static XInputGetState_t Original_XInputGetState = nullptr;
static XInputSetState_t Original_XInputSetState = nullptr;
static XInputGetCapabilities_t Original_XInputGetCapabilities = nullptr;
static XInputEnable_t Original_XInputEnable = nullptr;
static XInputGetDSoundAudioDeviceGuids_t Original_XInputGetDSoundAudioDeviceGuids = nullptr;
static XInputGetBatteryInformation_t Original_XInputGetBatteryInformation = nullptr;
static XInputGetKeystroke_t Original_XInputGetKeystroke = nullptr;
static XInputGetStateEx_t Original_XInputGetStateEx = nullptr;
static XInputWaitForGuideButton_t Original_XInputWaitForGuideButton = nullptr;
static XInputCancelGuideButtonWait_t Original_XInputCancelGuideButtonWait = nullptr;
static XInputPowerOffController_t Original_XInputPowerOffController = nullptr;

// 获取原始DLL句柄
HMODULE GetOriginalDLL()
{
    return g_originalDLL;
}

// 初始化代理
bool InitializeProxy()
{
    // 获取系统目录
    wchar_t systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);

    // 构建原始DLL路径
    std::wstring dllPath = std::wstring(systemPath) + L"\\xinput1_4.dll";

    // 加载原始DLL
    g_originalDLL = LoadLibraryW(dllPath.c_str());
    if (!g_originalDLL)
        return false;

    // 获取所有函数地址
    Original_XInputGetState = (XInputGetState_t)GetProcAddress(g_originalDLL, "XInputGetState");
    Original_XInputSetState = (XInputSetState_t)GetProcAddress(g_originalDLL, "XInputSetState");
    Original_XInputGetCapabilities = (XInputGetCapabilities_t)GetProcAddress(g_originalDLL, "XInputGetCapabilities");
    Original_XInputEnable = (XInputEnable_t)GetProcAddress(g_originalDLL, "XInputEnable");
    Original_XInputGetDSoundAudioDeviceGuids = (XInputGetDSoundAudioDeviceGuids_t)GetProcAddress(g_originalDLL, "XInputGetDSoundAudioDeviceGuids");
    Original_XInputGetBatteryInformation = (XInputGetBatteryInformation_t)GetProcAddress(g_originalDLL, "XInputGetBatteryInformation");
    Original_XInputGetKeystroke = (XInputGetKeystroke_t)GetProcAddress(g_originalDLL, "XInputGetKeystroke");
    
    // 这些是序号导出的隐藏函数
    Original_XInputGetStateEx = (XInputGetStateEx_t)GetProcAddress(g_originalDLL, (LPCSTR)100);
    Original_XInputWaitForGuideButton = (XInputWaitForGuideButton_t)GetProcAddress(g_originalDLL, (LPCSTR)101);
    Original_XInputCancelGuideButtonWait = (XInputCancelGuideButtonWait_t)GetProcAddress(g_originalDLL, (LPCSTR)102);
    Original_XInputPowerOffController = (XInputPowerOffController_t)GetProcAddress(g_originalDLL, (LPCSTR)103);

    return true;
}

// 清理代理
void CleanupProxy()
{
    if (g_originalDLL)
    {
        FreeLibrary(g_originalDLL);
        g_originalDLL = nullptr;
    }
}

// ==============================================
// 导出函数转发实现
// ==============================================

extern "C"
{
    __declspec(dllexport) DWORD WINAPI XInputGetState(DWORD dwUserIndex, void* pState)
    {
        if (Original_XInputGetState)
            return Original_XInputGetState(dwUserIndex, pState);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) DWORD WINAPI XInputSetState(DWORD dwUserIndex, void* pVibration)
    {
        if (Original_XInputSetState)
            return Original_XInputSetState(dwUserIndex, pVibration);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) DWORD WINAPI XInputGetCapabilities(DWORD dwUserIndex, DWORD dwFlags, void* pCapabilities)
    {
        if (Original_XInputGetCapabilities)
            return Original_XInputGetCapabilities(dwUserIndex, dwFlags, pCapabilities);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) void WINAPI XInputEnable(BOOL enable)
    {
        if (Original_XInputEnable)
            Original_XInputEnable(enable);
    }

    __declspec(dllexport) DWORD WINAPI XInputGetDSoundAudioDeviceGuids(DWORD dwUserIndex, void* pDSoundRenderGuid, void* pDSoundCaptureGuid)
    {
        if (Original_XInputGetDSoundAudioDeviceGuids)
            return Original_XInputGetDSoundAudioDeviceGuids(dwUserIndex, pDSoundRenderGuid, pDSoundCaptureGuid);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) DWORD WINAPI XInputGetBatteryInformation(DWORD dwUserIndex, BYTE devType, void* pBatteryInformation)
    {
        if (Original_XInputGetBatteryInformation)
            return Original_XInputGetBatteryInformation(dwUserIndex, devType, pBatteryInformation);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) DWORD WINAPI XInputGetKeystroke(DWORD dwUserIndex, DWORD dwReserved, void* pKeystroke)
    {
        if (Original_XInputGetKeystroke)
            return Original_XInputGetKeystroke(dwUserIndex, dwReserved, pKeystroke);
        return ERROR_EMPTY;
    }

    // 隐藏的扩展函数 (序号导出)
    __declspec(dllexport) DWORD WINAPI XInputGetStateEx(DWORD dwUserIndex, void* pState)
    {
        if (Original_XInputGetStateEx)
            return Original_XInputGetStateEx(dwUserIndex, pState);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) DWORD WINAPI XInputWaitForGuideButton(DWORD dwUserIndex, DWORD dwFlag, void* pVoid)
    {
        if (Original_XInputWaitForGuideButton)
            return Original_XInputWaitForGuideButton(dwUserIndex, dwFlag, pVoid);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) DWORD WINAPI XInputCancelGuideButtonWait(DWORD dwUserIndex)
    {
        if (Original_XInputCancelGuideButtonWait)
            return Original_XInputCancelGuideButtonWait(dwUserIndex);
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    __declspec(dllexport) DWORD WINAPI XInputPowerOffController(DWORD dwUserIndex)
    {
        if (Original_XInputPowerOffController)
            return Original_XInputPowerOffController(dwUserIndex);
        return ERROR_DEVICE_NOT_CONNECTED;
    }
}
