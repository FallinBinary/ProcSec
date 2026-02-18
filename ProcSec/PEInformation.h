#pragma once

#include "Header.h"

#define PE_LV_OPTIONAL_VALUE 1
#define PE_LV_IMPORT_FUNCNAME 1
#define PE_LV_IMPORT_FUNC_ORDINAL 2

typedef struct _TAB_HANDLES {
	HWND hTabListViewOptional;
	HWND hTabListViewImport;
} TAB_HANDLES, *PTAB_HANDLES;

BOOL GetPeInfo(PTAB_HANDLES pTabHandles, LPWSTR pPath);

BOOL GetOptionalInfo64(HANDLE hFile, PBYTE fileBuff, HWND hTabListViewOptional);
BOOL GetOptionalInfo32(HANDLE hFile, PBYTE fileBuff, HWND hTabListViewOptional);

BOOL GetImportInfo64(HANDLE hFile, PBYTE fileBuff, HWND  hTabListViewImport);
BOOL GetImportInfo32(HANDLE hFile, PBYTE fileBuff, HWND  hTabListViewImport);