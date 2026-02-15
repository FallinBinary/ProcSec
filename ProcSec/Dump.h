#pragma once

#include "Header.h"

#pragma comment(lib, "dbghelp.lib")

BOOL SaveDumpFilePath(HWND hWnd, LPWSTR fileName);
BOOL CreateDump(LPWSTR pId, LPWSTR fileName);