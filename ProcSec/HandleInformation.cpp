#include "HandleInformation.h"

BOOL GetTypeAndNameObject(HANDLE hProcess, HANDLE HandleValue, BYTE* TypeBuf, SIZE_T TypeBufSize, BYTE* NameBuf, SIZE_T NameBufSize);


BOOL GetHandleObjectInformation(HWND hTabListViewHandle, DWORD pID)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQuerySystemInformation = (NtQuerySystemInformation_t)::GetProcAddress(hNtdll, "NtQuerySystemInformation");

		::FreeLibrary(hNtdll);

		HANDLE hHeap = ::GetProcessHeap();
		PVOID buffer = NULL;
		ULONG bufferSize = 0x10000;
		ULONG returnLen = 0;
		NTSTATUS status;

		for (;;) {

			if (buffer) {
				::HeapFree(hHeap, 0, buffer);
				buffer = NULL;
			}

			buffer = ::HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
			if (!buffer) return FALSE;

			status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, bufferSize, &returnLen);
			if (status == STATUS_SUCCESS) break;

			else if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
				if (returnLen > bufferSize)
					bufferSize = (returnLen + (1 << 12));
				else bufferSize *= 2;
			}

			else {
				if (buffer) ::HeapFree(hHeap, 0, buffer);
				return FALSE;
			}
		}

		auto handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;

		INT index = 0;
		WCHAR value[128] = { 0 }, value2[0x1000] = { 0 };
		// SetItem
		LVITEMW item = { 0 };
		item.mask = LVIF_TEXT;

		for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
			
			PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX h = &handleInfo->Handles[i];
			if (::HandleToULong(h->UniqueProcessId) != pID) continue;

			HANDLE hProcess = OpenProcessWithDup(pID, FALSE);
			if (hProcess) {

				BYTE typeBuf[0x100] = { 0 }, nameBuf[0x1000] = { 0 };
				if (GetTypeAndNameObject(hProcess, h->HandleValue, typeBuf, sizeof(typeBuf), nameBuf, sizeof(nameBuf))) {

					item.iItem = index;

					auto typeInfo = (POBJECT_TYPE_INFORMATION)typeBuf;
					::swprintf_s(value, L"%wZ", &typeInfo->TypeName);
					ListView_InsertItem(hTabListViewHandle, &item);
					ListView_SetItemText(hTabListViewHandle, index, 0, const_cast<LPWSTR>(value));

					if (!::_wcsicmp(typeInfo->TypeName.Buffer, L"Process")) {
						::swprintf_s(value2, L"%ws", (WCHAR*)nameBuf);
					}
					else if (!::_wcsicmp(typeInfo->TypeName.Buffer, L"Thread")) {
						::swprintf_s(value2, L"%ws", (WCHAR*)nameBuf);
					}
					else if (!::_wcsicmp(typeInfo->TypeName.Buffer, L"Token")) {
						::swprintf_s(value2, L"%ws", (WCHAR*)nameBuf);
					}
					else {
						auto nameInfo = (POBJECT_NAME_INFORMATION)nameBuf;
						::swprintf_s(value2, L"%ws", nameInfo->Name.Length == 0 ? L"" : nameInfo->Name.Buffer);
					}
					ListView_SetItemText(hTabListViewHandle, index, 1, const_cast<LPWSTR>(value2));

					::swprintf_s(value, L"0x%X", ::HandleToULong(h->HandleValue));
					ListView_SetItemText(hTabListViewHandle, index, 2, const_cast<LPWSTR>(value));

					::swprintf_s(value, L"0x%X", h->GrantedAccess);
					ListView_SetItemText(hTabListViewHandle, index, 3, const_cast<LPWSTR>(value));

					index++;
				}
			}
		}

		::HeapFree(hHeap, 0, buffer);
		return TRUE;
	}
	return FALSE;
}


BOOL GetTypeAndNameObject(HANDLE hProcess, HANDLE HandleValue, BYTE* TypeBuf, SIZE_T TypeBufSize, BYTE* NameBuf, SIZE_T NameBufSize)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQueryObject = (NtQueryObject_t)::GetProcAddress(hNtdll, "NtQueryObject");
		auto NtDuplicateObject = (NtDuplicateObject_t)::GetProcAddress(hNtdll, "NtDuplicateObject");

		::FreeLibrary(hNtdll);

		NTSTATUS status;
		HANDLE dupHandle = nullptr, hDupThread = nullptr, hDupToken = nullptr;
		status = NtDuplicateObject(hProcess, HandleValue, ::GetCurrentProcess(), &dupHandle, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0);
		status = NtDuplicateObject(hProcess, HandleValue, ::GetCurrentProcess(), &hDupThread, THREAD_QUERY_LIMITED_INFORMATION, 0, 0);
		status = NtDuplicateObject(hProcess, HandleValue, ::GetCurrentProcess(), &hDupToken, TOKEN_QUERY, 0, 0);

		ULONG len;

		status = NtQueryObject(dupHandle, ObjectTypeInformation, TypeBuf, TypeBufSize, &len);
		if (status == STATUS_SUCCESS) {

			auto typeInfo = (POBJECT_TYPE_INFORMATION)TypeBuf;

			if (!::_wcsicmp(typeInfo->TypeName.Buffer, L"Process")) {
				DWORD pid = ::GetProcessId(dupHandle);
				BYTE* temp[0x1000] = { 0 };
				GetProcessFilePath(0, (WCHAR*)temp, dupHandle, TRUE);

				WCHAR* name = (::wcsrchr((WCHAR*)temp, L'\\') + 1);
				if (temp[0] != nullptr)
					::wsprintfW((WCHAR*)NameBuf, L"%ws (%d)", name, pid);
			}

			else if (!::_wcsicmp(typeInfo->TypeName.Buffer, L"Thread")) {
				DWORD tid = ::GetThreadId(hDupThread);
				DWORD pid = ::GetProcessIdOfThread(hDupThread);
				BYTE* temp[0x1000] = { 0 };
				GetProcessFilePath(pid, (WCHAR*)temp, nullptr, FALSE);

				WCHAR* name = (::wcsrchr((WCHAR*)temp, L'\\') + 1);
				if (temp[0] != nullptr)
					::wsprintfW((WCHAR*)NameBuf, L"%ws (%d): %d", name, pid, tid);
			}

			else if (!::_wcsicmp(typeInfo->TypeName.Buffer, L"Token")) {
				USERINFO ui = { 0 };
				TOKEN_TYPE tt;
				DWORD size;

				GetProcessUserInfo(0, &ui, hDupToken, TRUE);
				::GetTokenInformation(hDupToken, TokenType, &tt, sizeof(tt), &size);

				::wsprintfW((WCHAR*)NameBuf, L"%ws\\%ws (%ws)", ui.DomainName, ui.UserName, tt == TokenPrimary ? L"Primary" : L"Impersonate");
			}
			
			else
				status = NtQueryObject(dupHandle, ObjectNameInformation, NameBuf, NameBufSize, &len);

			SecureCloseHandle(dupHandle);
			SecureCloseHandle(hDupThread);
			SecureCloseHandle(hDupToken);
			
			if (status == STATUS_SUCCESS)
				return TRUE;
		}
	}

	return FALSE;
}