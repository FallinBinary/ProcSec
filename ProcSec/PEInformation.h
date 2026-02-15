#pragma once

#include "Header.h"

#define PE_LV_OPTIONAL_VALUE 1
#define PE_LV_IMPORT_FUNCNAME 1
#define PE_LV_IMPORT_FUNCADDR 2

BOOL GetPeInfo(HWND hTabListViewOptional, HWND hTabListViewImport, LPWSTR pId, LPWSTR pName);
BOOL GetOptionalInfo64(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND hTabListViewOptional);
BOOL GetOptionalInfo32(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND hTabListViewOptional);
BOOL GetImportInfo64(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND hTabListViewImport);
BOOL GetImportInfo32(HANDLE hProcess, BYTE* base, IMAGE_DOS_HEADER dosHeader, HWND hTabListViewImport);
BOOL IsProcess64(HANDLE hProcess);