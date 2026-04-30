#pragma once

#include "Header.h"


/* Structures */
typedef struct _PROTECTION
{
	wchar_t Type[16];
	wchar_t Audit[16];
	wchar_t Signer[16];
} PROTECTION, * PPROTECTION;

typedef struct _MITIGATION {
	DWORD DEPPolicy;
	DWORD ASLRPolicy;
	DWORD ControlFlowGuardPolicy;
} MITIGATION, * PMITIGATION;


/* Function Prototype */
void GetProcessMitigation(HANDLE hProcess, PMITIGATION m);
BOOL GetProcessProtection(HANDLE hProcess, PPROTECTION p);