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