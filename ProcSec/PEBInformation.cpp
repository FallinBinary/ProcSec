#include "PEBInformation.h"


BOOL GetPebInfo(HWND hDlg, LPWSTR pID, LPWSTR pName)
{
	PROCESS_EXTENDED_BASIC_INFORMATION pbi = { 0 };
	PEB peb = { 0 };

	GetProcessExtendedBasicInformation(_wtoi(pID), &pbi, sizeof(pbi));
	HANDLE hProcess = OpenProcessWithVMRead(_wtoi(pID), FALSE);

	if (pbi.PebBaseAddress != 0) {
		::ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr);

		PBYTE remoteCmd = (PBYTE)((PBYTE)(peb.ProcessParameters) + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine));
		UNICODE_STRING us = { 0 };

		BOOL bWow64Process = FALSE;
		WCHAR pPEB[32] = { 0 };
		WCHAR bBeingDebugged[8] = { 0 };
		WCHAR pImageBase[32] = { 0 };
		WCHAR pLdr[32] = { 0 };
		WCHAR pProcessParameter[512] = { 0 };

		::ReadProcessMemory(hProcess, remoteCmd, &us, sizeof(us), nullptr);
		::ReadProcessMemory(hProcess, us.Buffer, pProcessParameter, us.Length, nullptr);

		::wsprintfW(pPEB, L"0x%p", pbi.PebBaseAddress);
		::wsprintfW(bBeingDebugged, L"%d", peb.BeingDebugged);
		::wsprintfW(pImageBase, L"0x%p", peb.ImageBaseAddress);
		::wsprintfW(pLdr, L"0x%p", peb.Ldr);

		INT index = 0;
		WCHAR value[64] = { 0 };

		// SetItem
		LVITEMW item = { 0 };
		item.mask = LVIF_TEXT;

		item.iItem = index;
		item.pszText = const_cast<LPWSTR>(L"Process");
		ListView_InsertItem(hDlg, &item);
		ListView_SetItemText(hDlg, index++, 1, const_cast<LPWSTR>(pName));

		item.iItem = index;
		item.pszText = const_cast<LPWSTR>(L"Process ID");
		ListView_InsertItem(hDlg, &item);
		ListView_SetItemText(hDlg, index++, 1, const_cast<LPWSTR>(pID));

		item.iItem = index;
		item.pszText = const_cast<LPWSTR>(L"PEB Address");
		ListView_InsertItem(hDlg, &item);
		ListView_SetItemText(hDlg, index++, 1, const_cast<LPWSTR>(pPEB));

		item.iItem = index;
		item.pszText = const_cast<LPWSTR>(L"Being Debugged");
		ListView_InsertItem(hDlg, &item);
		ListView_SetItemText(hDlg, index++, 1, const_cast<LPWSTR>(bBeingDebugged));

		item.iItem = index;
		item.pszText = const_cast<LPWSTR>(L"Image Base Address");
		ListView_InsertItem(hDlg, &item);
		ListView_SetItemText(hDlg, index++, 1, const_cast<LPWSTR>(pImageBase));

		item.iItem = index;
		item.pszText = const_cast<LPWSTR>(L"LDR");
		ListView_InsertItem(hDlg, &item);
		ListView_SetItemText(hDlg, index++, 1, const_cast<LPWSTR>(pLdr));

		item.iItem = index;
		item.pszText = const_cast<LPWSTR>(L"Process Parameters");
		ListView_InsertItem(hDlg, &item);
		ListView_SetItemText(hDlg, index++, 1, const_cast<LPWSTR>(pProcessParameter));

		SecureCloseHandle(hProcess);
		return TRUE;
	}
	return FALSE;
}