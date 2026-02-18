#include "PEInformation.h"


BOOL GetPeInfo(PTAB_HANDLES pTabHandles, LPWSTR pPath)
{
	// Open file for read PE structure
	HANDLE hFile = ::CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		if (::GetLastError() == ERROR_ACCESS_DENIED)
			::MessageBoxW(nullptr, L"Error: Access is denied.", L"Process Security", MB_OK | MB_ICONERROR);
		else
			ShowErrorWithLastError(L"CreateFile");
		return FALSE;
	}

	DWORD fileSize = ::GetFileSize(hFile, nullptr);
	BYTE* fileBuff = (BYTE*)malloc(fileSize);
	
	if (fileBuff != NULL) {
		DWORD read = 0;
		if (::ReadFile(hFile, fileBuff, fileSize, &read, nullptr) == FALSE) {
			ShowErrorWithLastError(L"Read file");
			SecureCloseHandle(hFile);
			return FALSE;
		}

		// Get NTHeader.OptionalHeader.Magic
		WORD headerMagic = *(WORD*)(fileBuff + (*(DWORD*)&fileBuff[0x3C]) + sizeof(IMAGE_NT_HEADERS::Signature) + sizeof(IMAGE_NT_HEADERS::FileHeader));

		if (headerMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			GetOptionalInfo32(hFile, fileBuff, pTabHandles->hTabListViewOptional);
			GetImportInfo32(hFile, fileBuff, pTabHandles->hTabListViewImport);
		}
		else {
			GetOptionalInfo64(hFile, fileBuff, pTabHandles->hTabListViewOptional);
			GetImportInfo64(hFile, fileBuff, pTabHandles->hTabListViewImport);
		}
	}

	SecureCloseHandle(hFile);
	return TRUE;
}


BOOL GetOptionalInfo64(HANDLE hFile, PBYTE fileBuff, HWND hTabListViewOptional)
{
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((*(DWORD*)&fileBuff[0x3C]) + fileBuff);
	IMAGE_OPTIONAL_HEADER64 optionalHeader = ntHeader->OptionalHeader;
	
	INT index = 0;
	WCHAR value[64] = { 0 };

	// SetItem
	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT;

	item.iItem = index;
	::wsprintfW(value, L"%04X", optionalHeader.Magic);
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
	::wsprintfW(value, L"%Ix", (void* __ptr64)optionalHeader.ImageBase);
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


BOOL GetOptionalInfo32(HANDLE hFile, PBYTE fileBuff, HWND hTabListViewOptional)
{
	PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)((*(DWORD*)&fileBuff[0x3C]) + fileBuff);
	IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader->OptionalHeader;

	INT index = 0;
	WCHAR value[64] = { 0 };

	// SetItem
	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT;

	item.iItem = index;
	::wsprintfW(value, L"%04X", optionalHeader.Magic);
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
	::wsprintfW(value, L"%X", optionalHeader.BaseOfData);
	item.pszText = const_cast<LPWSTR>(L"BaseOfData");
	ListView_InsertItem(hTabListViewOptional, &item);
	ListView_SetItemText(hTabListViewOptional, index++, PE_LV_OPTIONAL_VALUE, const_cast<LPWSTR>(value));

	item.iItem = index;
	::wsprintfW(value, L"%Ix", (void* __ptr32)optionalHeader.ImageBase);
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


BOOL GetImportInfo64(HANDLE hFile, PBYTE fileBuff, HWND  hTabListViewImport)
{
	PIMAGE_NT_HEADERS64   ntHeader = (PIMAGE_NT_HEADERS64)((*(DWORD*)&fileBuff[0x3C]) + fileBuff);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHeader);
	IMAGE_DATA_DIRECTORY  importDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!importDir.VirtualAddress)
		return FALSE; // No Import!

	DWORD offset = 0;

	// Search for .idata section
	for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sec++) {
		DWORD start = sec->VirtualAddress;
		DWORD end = start + sec->SizeOfRawData;

		if (importDir.VirtualAddress >= start && importDir.VirtualAddress <= end) {
			offset = importDir.VirtualAddress - start + sec->PointerToRawData;
			break;
		}
	}

	int index = 0;

	for (;;) {
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(fileBuff + offset);

		CHAR* dllName = (CHAR*)(fileBuff + (importDesc->Name - sec->VirtualAddress + sec->PointerToRawData));

		if (importDesc->OriginalFirstThunk == 0 && importDesc->FirstThunk == 0) break;

		// Convert Ascii to Wide
		std::wstring ws(dllName, dllName + ::strlen(dllName));
		const wchar_t* wDllName = ws.c_str();

		PIMAGE_THUNK_DATA64 iatData = (PIMAGE_THUNK_DATA64)(fileBuff + (importDesc->FirstThunk - sec->VirtualAddress + sec->PointerToRawData));
		PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)(fileBuff + (iatData->u1.AddressOfData - sec->VirtualAddress + sec->PointerToRawData));

		for (;; iatData++, index++) {

			PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)(fileBuff + (iatData->u1.AddressOfData - sec->VirtualAddress + sec->PointerToRawData));

			if (!iatData->u1.AddressOfData) break;

			// SetItem
			LVITEMW item = { 0 };
			item.mask = LVIF_TEXT;
			item.iItem = index;
			item.pszText = const_cast<LPWSTR>(wDllName);
			ListView_InsertItem(hTabListViewImport, &item);

			if (!(iatData->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
				// Convert Ascii to Wide
				std::wstring ws(impName->Name, impName->Name + strlen(impName->Name));
				const wchar_t* wFuncName = ws.c_str();
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCNAME, const_cast<LPWSTR>(wFuncName));
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNC_ORDINAL, const_cast<LPWSTR>(L"-"));
			}
			else {
				wchar_t funcOrdinal[16] = { 0 };
				wsprintfW(funcOrdinal, L"%X", ((iatData->u1.Ordinal) & 0x0FFFFFFFFFFFFFFF));
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNC_ORDINAL, const_cast<LPWSTR>(funcOrdinal));
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCNAME, const_cast<LPWSTR>(L"-"));
			}
		}
		offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	return TRUE;
}


BOOL GetImportInfo32(HANDLE hFile, PBYTE fileBuff, HWND  hTabListViewImport)
{
	PIMAGE_NT_HEADERS32   ntHeader  = (PIMAGE_NT_HEADERS32)((*(DWORD*)&fileBuff[0x3C]) + fileBuff);
	PIMAGE_SECTION_HEADER sec       = IMAGE_FIRST_SECTION(ntHeader);
	IMAGE_DATA_DIRECTORY  importDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!importDir.VirtualAddress)
		return FALSE; // No Import!

	DWORD offset = 0;

	// Search for .idata section
	for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sec++) {
		DWORD start = sec->VirtualAddress;
		DWORD end = start + sec->SizeOfRawData;

		if (importDir.VirtualAddress >= start && importDir.VirtualAddress <= end) {
			offset = importDir.VirtualAddress - start + sec->PointerToRawData;
			break;
		}
	}

	int index = 0;

	for (;;) {
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(fileBuff + offset);

		CHAR* dllName = (CHAR*)(fileBuff + (importDesc->Name - sec->VirtualAddress + sec->PointerToRawData));

		if (importDesc->OriginalFirstThunk == 0 && importDesc->FirstThunk == 0) break;

		// Convert Ascii to Wide
		std::wstring ws(dllName, dllName + ::strlen(dllName));
		const wchar_t* wDllName = ws.c_str();

		PIMAGE_THUNK_DATA32 iatData = (PIMAGE_THUNK_DATA32)(fileBuff + (importDesc->FirstThunk - sec->VirtualAddress + sec->PointerToRawData));
		PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)(fileBuff + (iatData->u1.AddressOfData - sec->VirtualAddress + sec->PointerToRawData));

		for (;; iatData++, index++) {

			PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)(fileBuff + (iatData->u1.AddressOfData - sec->VirtualAddress + sec->PointerToRawData));

			if (!iatData->u1.AddressOfData) break;

			// SetItem
			LVITEMW item = { 0 };
			item.mask = LVIF_TEXT;
			item.iItem = index;
			item.pszText = const_cast<LPWSTR>(wDllName);
			ListView_InsertItem(hTabListViewImport, &item);

			if (!(iatData->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
				// Convert Ascii to Wide
				std::wstring ws(impName->Name, impName->Name + strlen(impName->Name));
				const wchar_t* wFuncName = ws.c_str();
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCNAME, const_cast<LPWSTR>(wFuncName));
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNC_ORDINAL, const_cast<LPWSTR>(L"-"));
			}
			else {
				wchar_t funcOrdinal[16] = { 0 };
				wsprintfW(funcOrdinal, L"%X", ((iatData->u1.Ordinal) & 0x0FFFFFFF));
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNC_ORDINAL, const_cast<LPWSTR>(funcOrdinal));
				ListView_SetItemText(hTabListViewImport, index, PE_LV_IMPORT_FUNCNAME, const_cast<LPWSTR>(L"-"));
			}
		}
		offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	return TRUE;
}