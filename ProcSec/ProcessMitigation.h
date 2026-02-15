#pragma once

#include "Header.h"

typedef struct _MITIGATION {
	DWORD DEPPolicy;
	DWORD ASLRPolicy;
	DWORD ControlFlowGuardPolicy;
} MITIGATION, * PMITIGATION;


void GetMitigation(HANDLE hProcess, PMITIGATION m);