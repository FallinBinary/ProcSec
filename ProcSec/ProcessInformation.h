#pragma once

#include "Header.h"


/* Structures */
typedef struct _PROTECTION {
	wchar_t Type[16];
	wchar_t Audit[16];
	wchar_t Signer[16];
} PROTECTION, * PPROTECTION;

typedef struct _MITIGATION {
	DWORD DEPPolicy;
	DWORD ASLRPolicy;
	DWORD ControlFlowGuardPolicy;
} MITIGATION, * PMITIGATION;

typedef struct _USERINFO {
	WCHAR UserName[UNLEN + 1];
	WCHAR DomainName[DNLEN + 1];
}USERINFO, * PUSERINFO;


/* Function Prototype */
HANDLE OpenProcessWithQueryLimitedInformation(DWORD pID, BOOLEAN showError);
HANDLE OpenProcessWithQueryInformation(DWORD pID, BOOLEAN showError);
HANDLE OpenProcessWithVMRead(DWORD pID, BOOLEAN showError);
////////////////////////////////////////////////////////////////////////////
BOOL EnumProc();
////////////////////////////////////////////////////////////////////////////
BOOL GetProcessMitigation(DWORD pID, PMITIGATION m);
BOOL GetProcessFilePath(DWORD pID, LPWSTR filename);
BOOL GetProcessCommandLine(DWORD pID, LPWSTR cmdline);
BOOL GetProcessExtendedBasicInformation(DWORD pID, PPROCESS_EXTENDED_BASIC_INFORMATION pbi, SIZE_T spbi);
BOOL GetProcessEnableLoggingInfo(DWORD pID, PPROCESS_LOGGING_INFORMATION pli, SIZE_T spli);
BOOL GetProcessProtection(DWORD pID, PPROTECTION p);
BOOL GetProcessUserInfo(DWORD pID, PUSERINFO pUserInfo);
////////////////////////////////////////////////////////////////////////////
BOOL IsProcess32(DWORD pID);
BOOL IsOwnProcess(DWORD pID);