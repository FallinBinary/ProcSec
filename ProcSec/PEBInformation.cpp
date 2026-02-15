#include "PEBInformation.h"


BOOL GetPebInfo(HWND hDlg, LPWSTR pId, LPWSTR pName)
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

		BOOL bWow64Process = FALSE;
		WCHAR pPEB[32] = { 0 };
		WCHAR bBeingDebugged[8] = { 0 };
		WCHAR pImageBase[32] = { 0 };
		WCHAR pLdr[32] = { 0 };
		WCHAR pProcessParameter[512] = { 0 };

		PEB peb = { 0 };

		if (pbi.PebBaseAddress != 0) {
			::ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr);

			PBYTE remoteCmd = (PBYTE)((PBYTE)(peb.ProcessParameters) + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine));
			UNICODE_STRING us = { 0 };

			::ReadProcessMemory(hProcess, remoteCmd, &us, sizeof(us), nullptr);
			::ReadProcessMemory(hProcess, us.Buffer, pProcessParameter, us.Length, nullptr);

			::wsprintfW(pPEB, L"0x%p", pbi.PebBaseAddress);
			::wsprintfW(bBeingDebugged, L"%d", peb.BeingDebugged);
			::wsprintfW(pImageBase, L"0x%p", peb.ImageBaseAddress);
			::wsprintfW(pLdr, L"0x%p", peb.Ldr);

			::SetDlgItemTextW(hDlg, IDC_STATIC_PEB_PNAME, pName);
			::SetDlgItemTextW(hDlg, IDC_STATIC_PEB_PID, pId);
			::SetDlgItemTextW(hDlg, IDC_STATIC_PEB, pPEB);
			::SetDlgItemTextW(hDlg, IDC_STATIC_BEINGDEBUGGED, bBeingDebugged);
			::SetDlgItemTextW(hDlg, IDC_STATIC_IMAGEBASE, pImageBase);
			::SetDlgItemTextW(hDlg, IDC_STATIC_LDR, pLdr);
			::SetDlgItemTextW(hDlg, IDC_STATIC_PARAMETER, pProcessParameter);

			SecureCloseHandle(hProcess);
			return TRUE;
		}
	}
	return FALSE;
}