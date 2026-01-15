#pragma once
#include <Windows.h>

// 获取原始DLL句柄
HMODULE GetOriginalDLL();

// 初始化代理 - 加载原始xinput1_4.dll
bool InitializeProxy();

// 清理代理
void CleanupProxy();
