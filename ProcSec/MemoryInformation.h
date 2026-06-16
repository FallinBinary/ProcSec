#pragma once

#include "Header.h"

#define TAB_LV_BASE_ADDRESS 0
#define TAB_LV_TYPE         1
#define TAB_LV_SIZE         2
#define TAB_LV_PROTECT      3


BOOL GetMemoryBasicInformation(HWND hTabListViewMemory, DWORD pID);