#include "MemoryInformation.h"


BOOL GetMemoryBasicInformation(DWORD pID)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQueryVirtualMemory = (NtQueryVirtualMemory_t)::GetProcAddress(hNtdll, "NtQueryVirtualMemory");

		::FreeLibrary(hNtdll);

		HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, FALSE);
		if (hProcess != NULL) {

			SIZE_T retLen;
			PBYTE address = 0;
			MEMORY_BASIC_INFORMATION mbi = { 0 };

			while (NtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen) >= 0) {
				address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
			}
			
			return EXIT_SUCCESS;
		}
	}
}