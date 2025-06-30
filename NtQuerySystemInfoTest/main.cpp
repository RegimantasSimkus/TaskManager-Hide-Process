#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

void main()
{
	SYSTEM_PROCESS_INFORMATION* pProcInfo = nullptr;

	ULONG dataSize = 0;
	NTSTATUS status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, nullptr, 0, &dataSize);
	printf("DataSize: %d\n", dataSize);

	pProcInfo = (SYSTEM_PROCESS_INFORMATION*)(new unsigned char[dataSize]);
	status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, pProcInfo, dataSize, nullptr);
	if (status == STATUS_SUCCESS)
	{
		printf("BEFORE:\n");
		for (SYSTEM_PROCESS_INFORMATION* pEntry = pProcInfo;;)
		{
			wprintf(L"[%.4X] %.*s\n", (unsigned int)pEntry->UniqueProcessId, (unsigned int)(pEntry->ImageName.Length / sizeof(WCHAR)), pEntry->ImageName.Buffer);

			ULONG offs = pEntry->NextEntryOffset;
			if (!offs)
				break;
			pEntry = (SYSTEM_PROCESS_INFORMATION*)((unsigned char*)pEntry + offs);
		}

#if 1
		SYSTEM_PROCESS_INFORMATION* pLastEntry = nullptr;
		SYSTEM_PROCESS_INFORMATION* pEntry = pProcInfo;
		while (1)
		{
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
			
			if (!pEntry->NextEntryOffset)
				break;
			pEntry = (SYSTEM_PROCESS_INFORMATION*)((unsigned char*)pEntry + pEntry->NextEntryOffset);
		}

		printf("AFTER:\n");
		for (SYSTEM_PROCESS_INFORMATION* pEntry = pProcInfo;;)
		{
			wprintf(L"[%.4X] %.*s\n", (unsigned int)pEntry->UniqueProcessId, (unsigned int)(pEntry->ImageName.Length / sizeof(WCHAR)), pEntry->ImageName.Buffer);
			
			ULONG offs = pEntry->NextEntryOffset;
			if (!offs)
				break;
			pEntry = (SYSTEM_PROCESS_INFORMATION*)((unsigned char*)pEntry + offs);
		}
#endif
	}

	delete[] pProcInfo;
}