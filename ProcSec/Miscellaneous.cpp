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


BOOL ConvertNtPathToDosPath(const WCHAR* ntPath, WCHAR* dosPath, DWORD dosPathSize) {
    WCHAR drives[512] = { 0 };

    if (GetLogicalDriveStringsW(512, drives) == 0) {
        return FALSE;
    }

    WCHAR* drive = drives;

    while (*drive) {
        WCHAR driveLetter[3] = { drive[0], drive[1], 0 };
        WCHAR devicePath[MAX_PATH] = { 0 };

        if (QueryDosDeviceW(driveLetter, devicePath, MAX_PATH)) {
            size_t deviceLen = wcslen(devicePath);
            
            if (_wcsnicmp(ntPath, devicePath, deviceLen) == 0) {
                swprintf(dosPath, dosPathSize, L"%s%s", driveLetter, ntPath + deviceLen);
                return TRUE;
            }
        }
        drive += wcslen(drive) + 1;
    }
    return FALSE;
}