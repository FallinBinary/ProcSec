#include "Miscellaneous.h"


void ShowErrorWithLastError(LPCWSTR sApiName)
{
	WCHAR errorMessage[256] = { 0 };
	::wsprintfW(errorMessage, L"%ws Failed with Error: %d", sApiName, ::GetLastError());
	::MessageBoxW(nullptr, errorMessage, L"Process Security", MB_OK | MB_ICONERROR);
}


void SecureCloseHandle(HANDLE handle)
{
	if (handle != NULL) {
		::CloseHandle(handle);
	}
}