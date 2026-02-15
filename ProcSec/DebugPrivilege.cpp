#include "DebugPrivilege.h"

BOOL SetDebugPrivilege()
{
	HANDLE hToken;

	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	LUID luid;

	if (!::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
		SecureCloseHandle(hToken);
		return FALSE;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL result = ::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);

	SecureCloseHandle(hToken);
	return result;
}