#pragma once
#include "hooking.h"

// a 64bit tramphook

// find nearby free page, stores the 64bit jump to the hook, and the patched instructions followed by a 64bit jump back to the target
BYTE* AllocHook(void* pTarget, int cbSize)
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);

	uintptr_t from = (uintptr_t)pTarget - 0x1FFFFFFF;
	uintptr_t to = (uintptr_t)pTarget + 0x1FFFFFFF;

	for (uintptr_t i = from; i < to; i += sysinfo.dwPageSize)
	{
		BYTE* alloc = (BYTE*)VirtualAlloc((LPVOID)i, cbSize + 14 + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (alloc)
			return alloc;
	}
	return nullptr;
}

void* TrampHook(BYTE* pTarget, void* pHook, int cbSize)
{
	if (!pTarget || !pHook || cbSize < 5)
		return nullptr;

	BYTE* pJMP = AllocHook(pTarget, cbSize);
	if (!pJMP)
		return nullptr;

	void* pReturn = nullptr;

	DWORD dwProtect;
	VirtualProtect(pTarget, cbSize, PAGE_EXECUTE_READWRITE, &dwProtect);
	{
		memcpy(pJMP + 14, pTarget, cbSize);

		// 32bit jmp to 64bit jmp
		*(BYTE*)pTarget = 0xE9;
		*(UINT*)(pTarget + 1) = (unsigned int)pJMP - (unsigned int)(pTarget + 5);

		pJMP[0] = 0xFF;
		pJMP[1] = 0x25;
		*(unsigned int*)(&pJMP[2]) = 0x00;
		*(uintptr_t*)(&pJMP[6]) = (uintptr_t)pHook;
		
		pJMP += 14;
		pReturn = pJMP;

		pJMP += cbSize;

		pJMP[0] = 0xFF;
		pJMP[1] = 0x25;
		*(unsigned int*)(&pJMP[2]) = 0x00;
		*(uintptr_t*)(&pJMP[6]) = (uintptr_t)(pTarget) + cbSize;
	}
	VirtualProtect(pTarget, cbSize, dwProtect, &dwProtect);
	FlushInstructionCache(GetCurrentProcess(), pTarget, cbSize);

	return (void*)pReturn;
}