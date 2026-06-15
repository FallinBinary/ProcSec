#include "MemoryInformation.h"

const wchar_t* StateToString(DWORD state);
const wchar_t* TypeToString(DWORD type);
const wchar_t* ProtectToString(DWORD protect);
void FormatNumberWithComma(SIZE_T value, WCHAR* out, int outSize);


BOOL GetMemoryBasicInformation(HWND hTabListViewProperties, DWORD pID)
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

			INT index = 0;
			WCHAR value[64] = { 0 };

			// SetItem
			LVITEMW item = { 0 };
			item.mask = LVIF_TEXT;

			while (NtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen) >= 0) {
				item.iItem = index;
				
				::swprintf_s(value, L"0x%llX", (unsigned long long)mbi.BaseAddress);
				ListView_InsertItem(hTabListViewProperties, &item);
				ListView_SetItemText(hTabListViewProperties, index, TAB_LV_BASE_ADDRESS, const_cast<LPWSTR>(value));

				 if (mbi.State != MEM_FREE)
					::swprintf_s(value, L"%ws: %ws", TypeToString(mbi.Type), StateToString(mbi.State));
				 else
					 ::swprintf_s(value, L"%ws", StateToString(mbi.State));
				ListView_SetItemText(hTabListViewProperties, index, TAB_LV_TYPE, const_cast<LPWSTR>(value));

				WCHAR size[128], value2[128];
				FormatNumberWithComma(mbi.RegionSize / 1024, size, 128);
				::swprintf_s(value2, L"%s kB", size);
				ListView_SetItemText(hTabListViewProperties, index, TAB_LV_SIZE, const_cast<LPWSTR>(value2));

				::swprintf_s(value, L"%ws", ProtectToString(mbi.Protect));
				ListView_SetItemText(hTabListViewProperties, index, TAB_LV_PROTECT, const_cast<LPWSTR>(value));

				index++;
				address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
			}
			
			return EXIT_SUCCESS;
		}
	}
}


const wchar_t* StateToString(DWORD state)
{
	switch (state)
	{
	case MEM_COMMIT:  return L"Commit";
	case MEM_RESERVE: return L"Reserve";
	case MEM_FREE:    return L"Free";
	default:          return L"Unknown";
	}
}


const wchar_t* TypeToString(DWORD type)
{
	switch (type)
	{
	case MEM_IMAGE:   return L"Image";
	case MEM_MAPPED:  return L"Mapped";
	case MEM_PRIVATE: return L"Private";
	default:          return L"Unknown";
	}
}


const wchar_t* ProtectToString(DWORD protect)
{
	wchar_t buf[128] = { 0 };

	switch (protect & 0xFF)
	{
	case PAGE_NOACCESS:
		wcsncat_s(buf, L"NA", sizeof(buf)); break;
	
	case PAGE_READONLY:
		wcsncat_s(buf, L"R", sizeof(buf)); break;
	
	case PAGE_READWRITE:
		wcsncat_s(buf, L"RW", sizeof(buf)); break;
	
	case PAGE_WRITECOPY:
		wcsncat_s(buf, L"WC", sizeof(buf)); break;
	
	case PAGE_EXECUTE:
		wcsncat_s(buf, L"X", sizeof(buf)); break;
	
	case PAGE_EXECUTE_READ:
		wcsncat_s(buf, L"RX", sizeof(buf)); break;
	
	case PAGE_EXECUTE_READWRITE:
		wcsncat_s(buf, L"RWX", sizeof(buf)); break;
	
	case PAGE_EXECUTE_WRITECOPY:
		wcsncat_s(buf, L"WCX", sizeof(buf)); break;
	
	default:
		wcsncat_s(buf, L"", sizeof(buf)); break;
	}

	if (protect & PAGE_GUARD)
		wcsncat_s(buf, L"+G", sizeof(buf) - 4);

	if (protect & PAGE_NOCACHE)
		wcsncat_s(buf, L"+N", sizeof(buf) - 4);

	if (protect & PAGE_WRITECOMBINE)
		wcsncat_s(buf, L"+WCM", sizeof(buf) - 4);

	return buf;
}


void FormatNumberWithComma(SIZE_T value, WCHAR* out, int outSize)
{
	NUMBERFMTW fmt = { 0 };

	fmt.Grouping = 3;
	fmt.lpDecimalSep = (LPWSTR)L",";
	fmt.lpThousandSep = (LPWSTR)L",";
	fmt.NegativeOrder = 1;

	WCHAR temp[64];
	swprintf_s(temp, L"%llu", (unsigned long long)value);

	GetNumberFormatW(LOCALE_USER_DEFAULT, 0, temp, &fmt, out, outSize);
}