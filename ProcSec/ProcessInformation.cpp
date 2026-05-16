#include "ProcessInformation.h"


HANDLE OpenProcessWithQueryLimitedInformation(DWORD pID, BOOLEAN showError)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pID);
	if (hProcess == NULL) {
		if (showError == TRUE) {
			if (::GetLastError() == ERROR_ACCESS_DENIED)
				::MessageBoxW(nullptr, L"Error: Access is denied.", L"Process Security", MB_OK | MB_ICONERROR);
			else
				ShowErrorWithLastError(L"OpenProcess");
		}
		return NULL;
	}
	return hProcess;
}


HANDLE OpenProcessWithVMRead(DWORD pID, BOOLEAN showError)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pID);
	if (hProcess == NULL) {
		if (showError == TRUE) {
			if (::GetLastError() == ERROR_ACCESS_DENIED)
				::MessageBoxW(nullptr, L"Error: Access is denied.", L"Process Security", MB_OK | MB_ICONERROR);
			else
				ShowErrorWithLastError(L"OpenProcess");
		}
		return NULL;
	}
	return hProcess;
}


BOOL GetProcessBasicInformation(DWORD pID, PPROCESS_BASIC_INFORMATION pbi, SIZE_T spbi)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hNtdll, "NtQueryInformationProcess");

		::FreeLibrary(hNtdll);

		HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, TRUE);
		if (hProcess != NULL) {
			ULONG nRetLen;
			NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, spbi, &nRetLen);
			return TRUE;
		}
	}
	return FALSE;
}


BOOL GetProcessEnableLoggingInfo(DWORD pID, PPROCESS_LOGGING_INFORMATION pli, SIZE_T spli)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hNtdll, "NtQueryInformationProcess");

		::FreeLibrary(hNtdll);

		HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, FALSE);
		if (hProcess != NULL) {
			ULONG nRetLen = 0;
			NTSTATUS res = NtQueryInformationProcess(hProcess, ProcessEnableLogging, pli, spli, &nRetLen);
			return TRUE;
		}
	}
	return FALSE;
}


BOOL GetProcessProtection(DWORD pID, PPROTECTION p)
{
	HMODULE ntdll = ::LoadLibraryW(L"ntdll.dll");
	if (ntdll != NULL) {
		NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(ntdll, "NtQueryInformationProcess");

		::FreeLibrary(ntdll);

		//const wchar_t* protectAudit[] = { L"False", L"True" };
		const wchar_t* protectType[] = { L"", L"PPL", L"Protected", L"Max" };
		const wchar_t* protectSigner[] = { L"", L"Autheticode", L"CodeGen", L"AntiMalware",
											 L"Lsa", L"Windows", L"WinTcb", L"WinSystem" };

		HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, FALSE);

		PS_PROTECTION pp = { 0 };
		ULONG nRetLen;
		NTSTATUS res = NtQueryInformationProcess(hProcess, ProcessProtectionInformation, &pp, sizeof(pp), &nRetLen);

		::wcsncpy_s(p->Type, protectType[pp.Type], sizeof(p->Type));
		::wcsncpy_s(p->Signer, protectSigner[pp.Signer], sizeof(p->Signer));
		// ::wcsncpy_s(p->Audit, protectAudit[pp.Audit], sizeof(p->Audit));

		SecureCloseHandle(hProcess);

		return TRUE;
	}

	return FALSE;
}


void GetProcessMitigation(HANDLE hProcess, PMITIGATION m)
{
	PROCESS_MITIGATION_DEP_POLICY dep{ 0 };
	if (!::GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep)))
		m->DEPPolicy = -1;
	else
		m->DEPPolicy = dep.Enable;

	PROCESS_MITIGATION_ASLR_POLICY aslr{ 0 };
	if (!::GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr)))
		m->ASLRPolicy = -1;
	else
		m->ASLRPolicy = aslr.EnableBottomUpRandomization;

	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{ 0 };
	if (!::GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)))
		m->ControlFlowGuardPolicy = -1;
	else
		m->ControlFlowGuardPolicy = cfg.EnableControlFlowGuard;
}


BOOL GetProcessUserInfo(DWORD pID, PUSERINFO pUserInfo)
{
	HANDLE hToken = 0;
	DWORD retLen = 0;
	BYTE buffer[1 << 12] = { 0 };
	WCHAR stringSid[32] = { 0 };
	WCHAR userName[UNLEN + 1] = { 0 };
	DWORD userNameSize = _countof(userName);
	WCHAR domainName[DNLEN + 1] = { 0 };
	DWORD domainNameSize = _countof(domainName);
	SID_NAME_USE use;

	HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, FALSE);
	if (hProcess != NULL) {

		if (::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {

			::GetTokenInformation(hToken, TokenUser, &buffer, sizeof(buffer), &retLen);
			PTOKEN_USER tUser = (PTOKEN_USER)buffer;

			ConvertSidToStringSidW(tUser->User.Sid, (LPWSTR*)&stringSid);
			LookupAccountSidW(nullptr, tUser->User.Sid, pUserInfo->UserName, &userNameSize, pUserInfo->DomainName, &domainNameSize, &use);

			return TRUE;
		}
	}
	return FALSE;
}


BOOL IsProcess32(DWORD pID)
{
	HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, FALSE);
	if (hProcess != NULL) {

		BOOL res = 0;
		IsWow64Process(hProcess, &res);

		return res;
	}
	return FALSE;
}


BOOL IsOwnProcess(DWORD pID)
{
	USERINFO currentUserInfo = { 0 };
	USERINFO targetUserInfo = { 0 };
	GetProcessUserInfo(GetCurrentProcessId(), &currentUserInfo);
	GetProcessUserInfo(pID, &targetUserInfo);

	if (!_wcsnicmp(currentUserInfo.UserName, targetUserInfo.UserName, sizeof(currentUserInfo.UserName)))
		if (!_wcsnicmp(currentUserInfo.DomainName, targetUserInfo.DomainName, sizeof(currentUserInfo.DomainName)))
			return TRUE;

	return FALSE;
}