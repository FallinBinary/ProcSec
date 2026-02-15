#include "PEInformation.h"


BOOL GetPeInfo(HWND hTabListViewOptional, HWND hTabListViewImport, LPWSTR pId, LPWSTR pName)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hNtdll, "NtQueryInformationProcess");

		::FreeLibrary(hNtdll);

		HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ::_wtoi(pId));
		if (hProcess == NULL) {
			if (::GetLastError() == ERROR_ACCESS_DENIED)
				::MessageBoxW(nullptr, L"Error: Access is denied.", L"Process Security", MB_OK | MB_ICONERROR);
			else
				ShowErrorWithLastError(L"OpenProcess");
			return FALSE;
		}

		PROCESS_BASIC_INFORMATION pbi = { 0 };
		ULONG nRetLen;
		NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &nRetLen);

		PEB peb = { 0 };
		IMAGE_DOS_HEADER dosHeader = { 0 };

		if (pbi.PebBaseAddress != 0) {
			::ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr);
			::ReadProcessMemory(hProcess, peb.ImageBaseAddress, &dosHeader, sizeof(dosHeader), nullptr);

			BOOL isWow64 = FALSE;
			BOOL res = ::IsWow64Process(hProcess, &isWow64);
			if (isWow64) {
				GetOptionalInfo32(hProcess, (BYTE*)peb.ImageBaseAddress, dosHeader, hTabListViewOptional);
				GetImportInfo32(hProcess, (BYTE*)peb.ImageBaseAddress, dosHeader, hTabListViewImport);
			}
			else {
				GetOptionalInfo64(hProcess, (BYTE*)peb.ImageBaseAddress, dosHeader, hTabListViewOptional);
				GetImportInfo64(hProcess, (BYTE*)peb.ImageBaseAddress, dosHeader, hTabListViewImport);
			}
		}

		SecureCloseHandle(hProcess);
	}

	return TRUE;
}


BOOL GetOptionalInfo64(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND hTabListViewOptional)
{
	IMAGE_NT_HEADERS64 ntHeader = { 0 };
	::ReadProcessMemory(hProcess, (BYTE*)base + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr);

	IMAGE_OPTIONAL_HEADER64 optionalHeader = ntHeader.OptionalHeader;

	int index = 0;
	wchar_t value[64] = { 0 };

	// SetItem
	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT;

	item.iItem = index;
	::wsprintfW(value, L"0x%04X", optionalHeader.Magic);
	item.pszText = const_cast<LPWSTR>(L"Magic");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorLinkerVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorLinkerVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorLinkerVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorLinkerVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfCode);
	item.pszText = const_cast<LPWSTR>(L"SizeOfCode");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfInitializedData);
	item.pszText = const_cast<LPWSTR>(L"SizeOfInitializedData");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfUninitializedData);
	item.pszText = const_cast<LPWSTR>(L"SizeOfUninitializedData");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.AddressOfEntryPoint);
	item.pszText = const_cast<LPWSTR>(L"AddressOfEntryPoint");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.BaseOfCode);
	item.pszText = const_cast<LPWSTR>(L"BaseOfCode");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.ImageBase);
	item.pszText = const_cast<LPWSTR>(L"ImageBase");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SectionAlignment);
	item.pszText = const_cast<LPWSTR>(L"SectionAlignment");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.FileAlignment);
	item.pszText = const_cast<LPWSTR>(L"FileAlignment");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorOperatingSystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorOperatingSystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorOperatingSystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorOperatingSystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorImageVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorImageVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorImageVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorImageVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorSubsystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorSubsystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorSubsystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorSubsystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.Win32VersionValue);
	item.pszText = const_cast<LPWSTR>(L"Win32VersionValue");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfImage);
	item.pszText = const_cast<LPWSTR>(L"SizeOfImage");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfHeaders);
	item.pszText = const_cast<LPWSTR>(L"SizeOfHeaders");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.CheckSum);
	item.pszText = const_cast<LPWSTR>(L"CheckSum");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.Subsystem);
	item.pszText = const_cast<LPWSTR>(L"Subsystem");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.DllCharacteristics);
	item.pszText = const_cast<LPWSTR>(L"DllCharacteristics");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfStackReserve);
	item.pszText = const_cast<LPWSTR>(L"SizeOfStackReserve");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfStackCommit);
	item.pszText = const_cast<LPWSTR>(L"SizeOfStackCommit");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfHeapReserve);
	item.pszText = const_cast<LPWSTR>(L"SizeOfHeapReserve");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfHeapCommit);
	item.pszText = const_cast<LPWSTR>(L"SizeOfHeapCommit");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.LoaderFlags);
	item.pszText = const_cast<LPWSTR>(L"LoaderFlags");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.NumberOfRvaAndSizes);
	item.pszText = const_cast<LPWSTR>(L"NumberOfRvaAndSizes");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	return TRUE;
}


BOOL GetOptionalInfo32(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND hTabListViewOptional)
{
	IMAGE_NT_HEADERS32 ntHeader = { 0 };
	::ReadProcessMemory(hProcess, (BYTE*)base + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr);

	IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader.OptionalHeader;

	int index = 0;
	wchar_t value[64] = { 0 };

	// SetItem
	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT;

	item.iItem = index;
	::wsprintfW(value, L"0x%04X", optionalHeader.Magic);
	item.pszText = const_cast<LPWSTR>(L"Magic");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorLinkerVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorLinkerVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorLinkerVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorLinkerVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfCode);
	item.pszText = const_cast<LPWSTR>(L"SizeOfCode");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfInitializedData);
	item.pszText = const_cast<LPWSTR>(L"SizeOfInitializedData");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfUninitializedData);
	item.pszText = const_cast<LPWSTR>(L"SizeOfUninitializedData");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.AddressOfEntryPoint);
	item.pszText = const_cast<LPWSTR>(L"AddressOfEntryPoint");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.BaseOfCode);
	item.pszText = const_cast<LPWSTR>(L"BaseOfCode");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.ImageBase);
	item.pszText = const_cast<LPWSTR>(L"ImageBase");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SectionAlignment);
	item.pszText = const_cast<LPWSTR>(L"SectionAlignment");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.FileAlignment);
	item.pszText = const_cast<LPWSTR>(L"FileAlignment");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorOperatingSystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorOperatingSystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorOperatingSystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorOperatingSystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorImageVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorImageVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorImageVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorImageVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MajorSubsystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MajorSubsystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.MinorSubsystemVersion);
	item.pszText = const_cast<LPWSTR>(L"MinorSubsystemVersion");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.Win32VersionValue);
	item.pszText = const_cast<LPWSTR>(L"Win32VersionValue");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfImage);
	item.pszText = const_cast<LPWSTR>(L"SizeOfImage");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfHeaders);
	item.pszText = const_cast<LPWSTR>(L"SizeOfHeaders");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.CheckSum);
	item.pszText = const_cast<LPWSTR>(L"CheckSum");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.Subsystem);
	item.pszText = const_cast<LPWSTR>(L"Subsystem");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.DllCharacteristics);
	item.pszText = const_cast<LPWSTR>(L"DllCharacteristics");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfStackReserve);
	item.pszText = const_cast<LPWSTR>(L"SizeOfStackReserve");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfStackCommit);
	item.pszText = const_cast<LPWSTR>(L"SizeOfStackCommit");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfHeapReserve);
	item.pszText = const_cast<LPWSTR>(L"SizeOfHeapReserve");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.SizeOfHeapCommit);
	item.pszText = const_cast<LPWSTR>(L"SizeOfHeapCommit");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.LoaderFlags);
	item.pszText = const_cast<LPWSTR>(L"LoaderFlags");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%X", optionalHeader.NumberOfRvaAndSizes);
	item.pszText = const_cast<LPWSTR>(L"NumberOfRvaAndSizes");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	return TRUE;
}


BOOL GetImportInfo64(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND  hTabListViewImport)
{
	IMAGE_DATA_DIRECTORY importDir = { 0 };
	IMAGE_IMPORT_DESCRIPTOR importDesc = { 0 };
	IMAGE_NT_HEADERS64 ntHeader = { 0 };
	CHAR dllName[256] = { 0 };
	CHAR funcName[256] = { 0 };
	int index = 0;

	::ReadProcessMemory(hProcess, (BYTE*)base + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr);
	importDir = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // .idata Section
	if (!importDir.VirtualAddress)
		return FALSE; // No Import!

	BYTE* descAddr = (BYTE*)base + importDir.VirtualAddress;

	for (;;) {
		::ReadProcessMemory(hProcess, descAddr, &importDesc, sizeof(importDesc), nullptr);
		if (!importDesc.Name) break;
		::ReadProcessMemory(hProcess, (BYTE*)base + importDesc.Name, dllName, sizeof(dllName), nullptr);

		// Convert Ascii to Wide
		std::wstring ws(dllName, dllName + ::strlen(dllName));
		const wchar_t* wDllName = ws.c_str();

		BYTE* thunk = (BYTE*)base + importDesc.OriginalFirstThunk;
		BYTE* iat = (BYTE*)base + importDesc.FirstThunk;

		for (;;) {
			DWORD64 thunkData = 0;
			DWORD64 iatData   = 0;

			::ReadProcessMemory(hProcess, thunk, &thunkData, sizeof(thunkData), nullptr);
			if (!thunkData) break;

			::ReadProcessMemory(hProcess, (BYTE*)base + thunkData + 2, funcName, sizeof(funcName), nullptr);
			::ReadProcessMemory(hProcess, iat, &iatData, sizeof(iatData), nullptr);

			// Convert Ascii to Wide
			std::wstring ws(funcName, funcName + strlen(funcName));
			const wchar_t* wFuncName = ws.c_str();

			wchar_t funcAddr[64] = { 0 };
			::wsprintfW(funcAddr, L"0x%p", iatData);
			
			// SetItem
			LVITEMW item = { 0 };
			item.mask = LVIF_TEXT;
			item.iItem = index;
			item.pszText = const_cast<LPWSTR>(wDllName);
			ListView_InsertItem(hTabListViewImport, &item);
			ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCNAME, const_cast<LPWSTR>(wFuncName));
			ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCADDR, const_cast<LPWSTR>(funcAddr));

			index++;
			thunk += sizeof(DWORD64);
			iat   += sizeof(DWORD64);
		}
		descAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	return TRUE;
}


BOOL GetImportInfo32(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND  hTabListViewImport)
{
	IMAGE_DATA_DIRECTORY importDir = { 0 };
	IMAGE_IMPORT_DESCRIPTOR importDesc = { 0 };
	IMAGE_NT_HEADERS32 ntHeader = { 0 };
	CHAR dllName[256] = { 0 };
	CHAR funcName[256] = { 0 };
	int index = 0;

	::ReadProcessMemory(hProcess, (BYTE*)base + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader), nullptr);
	importDir = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // .idata Section
	if (!importDir.VirtualAddress)
		return FALSE; // No Import!

	BYTE* descAddr = (BYTE*)base + importDir.VirtualAddress;

	for (;;) {
		::ReadProcessMemory(hProcess, descAddr, &importDesc, sizeof(importDesc), nullptr);
		if (!importDesc.Name) break;
		::ReadProcessMemory(hProcess, (BYTE*)base + importDesc.Name, dllName, sizeof(dllName), nullptr);

		// Convert Ascii to Wide
		std::wstring ws(dllName, dllName + strlen(dllName));
		const wchar_t* wDllName = ws.c_str();

		// thunk is a pointer
		BYTE* thunk = (BYTE*)base + importDesc.OriginalFirstThunk;
		BYTE* iat = (BYTE*)base + importDesc.FirstThunk;

		for (;;) {
			DWORD32 thunkData = 0;
			DWORD32 iatData = 0;

			::ReadProcessMemory(hProcess, thunk, &thunkData, sizeof(thunkData), nullptr);
			if (!thunkData) break;

			::ReadProcessMemory(hProcess, (BYTE*)base + thunkData + 2, funcName, sizeof(funcName), nullptr);
			::ReadProcessMemory(hProcess, iat, &iatData, sizeof(iatData), nullptr);

			// Convert Ascii to Wide
			std::wstring ws(funcName, funcName + strlen(funcName));
			const wchar_t* wFuncName = ws.c_str();

			wchar_t funcAddr[64] = { 0 };
			::wsprintfW(funcAddr, L"0x%p", iatData);

			// SetItem
			LVITEMW item = { 0 };
			item.mask = LVIF_TEXT;
			item.iItem = index;
			item.pszText = const_cast<LPWSTR>(wDllName);
			ListView_InsertItem(hTabListViewImport, &item);
			ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCNAME, const_cast<LPWSTR>(wFuncName));
			ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCADDR, const_cast<LPWSTR>(funcAddr));

			index++;
			thunk += sizeof(DWORD32);
			iat += sizeof(DWORD32);
		}
		descAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	return TRUE;
}


BOOL IsProcess64(HANDLE hProcess)
{
	USHORT p, m;
	if (!::IsWow64Process2(hProcess, &p, &m))
		return FALSE;

	return (m == IMAGE_FILE_MACHINE_AMD64);
}