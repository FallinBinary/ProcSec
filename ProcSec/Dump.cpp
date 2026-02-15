#include "Dump.h"


BOOL SaveDumpFilePath(HWND hWnd, LPWSTR fileName)
{
	OPENFILENAME ofn = { 0 };

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = hWnd;
	ofn.lpstrFile = fileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"Dump File (*.DMP)\0*.DMP\0";
	ofn.nFilterIndex = 1;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

	if (!::GetSaveFileNameW(&ofn))
		return FALSE;

	return TRUE;
}


BOOL CreateDump(LPWSTR pId, LPWSTR fileName)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ::_wtoi(pId));
	if (hProcess == NULL) {
		if (::GetLastError() == ERROR_ACCESS_DENIED)
			::MessageBoxW(nullptr, L"Error writing dump file: Access is denied.", L"Process Security", MB_OK | MB_ICONERROR);
		else
			ShowErrorWithLastError(L"OpenProcess");
		return FALSE;
	}

	HANDLE hFile = ::CreateFileW(fileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		ShowErrorWithLastError(L"CreateFile");
		SecureCloseHandle(hProcess);
		return FALSE;
	}

	if (::MiniDumpWriteDump(hProcess, ::_wtoi(pId), hFile, MiniDumpWithFullMemory, nullptr, nullptr, nullptr) == FALSE) {
		ShowErrorWithLastError(L"Dump Operation");
		SecureCloseHandle(hFile);
		SecureCloseHandle(hProcess);
		return FALSE;
	}

	::MessageBoxW(nullptr, L"Process Dump Completed Successfully.", L"Process Security", MB_OK | MB_ICONINFORMATION);
	return TRUE;
}