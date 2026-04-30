#include "ProcessInformation.h"


BOOL GetProcessProtection(HANDLE hProcess, PPROTECTION p)
{
	HMODULE ntdll = ::LoadLibraryW(L"ntdll.dll");
	if (ntdll != NULL) {
		NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(ntdll, "NtQueryInformationProcess");

		::FreeLibrary(ntdll);

		//const wchar_t* protectAudit[] = { L"False", L"True" };
		const wchar_t* protectType[] = { L"", L"PPL", L"Protected", L"Max" };
		const wchar_t* protectSigner[] = { L"", L"Autheticode", L"CodeGen", L"AntiMalware",
											 L"Lsa", L"Windows", L"WinTcb", L"WinSystem" };

		PS_PROTECTION pp = { 0 };
		ULONG nRetLen;
		NTSTATUS res = NtQueryInformationProcess(hProcess, ProcessProtectionInformation, &pp, sizeof(pp), &nRetLen);

		::wcsncpy_s(p->Type, protectType[pp.Type], sizeof(p->Type));
		::wcsncpy_s(p->Signer, protectSigner[pp.Signer], sizeof(p->Signer));
		// ::wcsncpy_s(p->Audit, protectAudit[pp.Audit], sizeof(p->Audit));

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


BOOL GetProcessUserInfo(int pID, PUSERINFO pUserInfo)
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

	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pID);
	if (!hProcess)
		return FALSE;

	if (!::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		return FALSE; 

	::GetTokenInformation(hToken, TokenUser, &buffer, sizeof(buffer), &retLen);
	PTOKEN_USER tUser = (PTOKEN_USER)buffer;

	ConvertSidToStringSidW(tUser->User.Sid, (LPWSTR*)&stringSid);
	LookupAccountSidW(nullptr, tUser->User.Sid, pUserInfo->UserName, &userNameSize, pUserInfo->DomainName, &domainNameSize, &use);

	return TRUE;
}