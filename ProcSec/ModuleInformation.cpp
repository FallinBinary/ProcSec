#include "ModuleInformation.h"


void SizeToString(wchar_t* Out, int OutSize, unsigned long Size);


BOOL GetProcessModuleInformation(HWND hTabListViewModules, DWORD pID)
{
	PROCESS_EXTENDED_BASIC_INFORMATION pbi = { 0 };
	PEB peb = { 0 };
	PEB_LDR_DATA ldr = { 0 };

	GetProcessExtendedBasicInformation(pID, &pbi, sizeof(pbi));
	HANDLE hProcess = OpenProcessWithVMRead(pID, FALSE);

	if (pbi.PebBaseAddress != 0 && hProcess != nullptr) {
		::ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr);
		::ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), nullptr);

		PLIST_ENTRY head = ldr.InLoadOrderModuleList.Flink;
		PLIST_ENTRY current = ldr.InLoadOrderModuleList.Flink;

		WCHAR value[64] = { 0 };
		int index = 0;

		// SetItem
		LVITEMW item = { 0 };
		item.mask = LVIF_TEXT;
		item.iItem = index;

		do {
			PLDR_DATA_TABLE_ENTRY pData = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			LDR_DATA_TABLE_ENTRY data = { 0 };
			WCHAR name[MAX_PATH] = { 0 };

			::ReadProcessMemory(hProcess, pData, &data, sizeof(data), nullptr);

			if (data.SizeOfImage != 0 && data.DllBase != 0) {

				// ============================================================================
				::ReadProcessMemory(hProcess, data.BaseDllName.Buffer, name, data.BaseDllName.Length, nullptr);
				item.pszText = name;
				ListView_InsertItem(hTabListViewModules, &item);
				//ListView_SetItemText(hTabListViewModules, index, 0, const_cast<LPWSTR>(name));

				::swprintf_s(value, L"0x%p", data.DllBase);
				ListView_SetItemText(hTabListViewModules, index, 1, const_cast<LPWSTR>(value));

				SizeToString(value, 64, data.SizeOfImage);
				ListView_SetItemText(hTabListViewModules, index, 2, const_cast<LPWSTR>(value));

				::ReadProcessMemory(hProcess, data.FullDllName.Buffer, name, data.FullDllName.Length, nullptr);
				ListView_SetItemText(hTabListViewModules, index, 3, const_cast<LPWSTR>(name));
				// ============================================================================
			
			}

			item.iItem = ++index;
			current = data.InLoadOrderLinks.Flink;

		} while (head != current);

		return TRUE;
	}
	return FALSE;
}


void SizeToString(wchar_t* Out, int OutSize, unsigned long Size)
{
	float finalSize = Size;
	int i;

	for (i = 0; finalSize > 1024; i++) {
		finalSize /= 1024.0;
	}

	switch (i)
	{
		case 0:
			swprintf_s(Out, OutSize, L"%lu B", Size); break;
		case 1:
			swprintf_s(Out, OutSize, L"%.2f kB", finalSize); break;
		case 2:
			swprintf_s(Out, OutSize, L"%.2f MB", finalSize); break;
		case 3:
			swprintf_s(Out, OutSize, L"%.2f GB", finalSize); break;
	}
}