#pragma once
#include <Windows.h>

void* TrampHook(BYTE* pTarget, void* pHook, int cbSize);