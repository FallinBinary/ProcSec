#pragma once

#include "Header.h"

#include "ProcessMitigation.h"
#include "ProcessProtection.h"
#include "DebugPrivilege.h"
#include "PEBInformation.h"
#include "PEInformation.h"
#include "Dump.h"

#pragma comment(lib, "comctl32.lib")


/* List View MACRO */
#define LV_PNAME   0
#define LV_PID	   1
#define LV_PPID    2
#define LV_PROTECT 3
#define LV_ASLR    4
#define LV_DEP     5
#define LV_CFG     6
#define LV_PATH    7
/* Popup Menu MACRO */
#define PM_PEB_INFO 100
#define PM_PE_INFO  200
#define PM_DUMP     300
/* Tab Macro */
#define TAB1 1000
#define TAB2 2000
#define TAB_LV_OPTIONAL_NAME   0
#define TAB_LV_OPTIONAL_VALUE  1
#define TAB_LV_IMPORT_DLLNAME  0
#define TAB_LV_IMPORT_FUNCNAME 1
#define TAB_LV_IMPORT_FUNC_ORDINAL 2


/* Function Prototype */
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK PEBDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PEDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
int CALLBACK CompareOriginal(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

void AddColumns(HWND hList);
void AddItem(HWND hList, int index, PPROCESSENTRY32W pe, wchar_t* path, PMITIGATION m, PPROTECTION p);
void GetProcessList(HWND hList);


/* Global Variables */
HINSTANCE hInst;
HWND hList;
HWND hTabDialogOptional;
HWND hTabDialogImport;
HWND hTab;

int g_SortColumn = -1;
int g_SortState = 0;
// 0 = no sort
// 1 = ascending
// 2 = descending


/* Structure */
typedef struct _PROC_ITEM {
	WCHAR name[MAX_PATH];
	DWORD pid;
	DWORD ppid;
	int originalIndex;
} PROC_ITEM, *PPROC_ITEM;