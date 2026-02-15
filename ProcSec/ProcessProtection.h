#pragma once

#include "Header.h"


typedef struct _PROTECTION
{
	wchar_t Type[16];
	wchar_t Audit[16];
	wchar_t Signer[16];
} PROTECTION, * PPROTECTION;


BOOL GetProtection(HANDLE hProcess, PPROTECTION p);