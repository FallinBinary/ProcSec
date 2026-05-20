#pragma once

#include "Header.h"


void ShowErrorWithLastError(LPCWSTR sApiName);
void SecureCloseHandle(HANDLE handle);
BOOL ConvertNtPathToDosPath(const WCHAR* ntPath, WCHAR* dosPath, DWORD dosPathSize);