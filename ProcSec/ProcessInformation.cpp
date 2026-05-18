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


HANDLE OpenProcessWithQueryInformation(DWORD pID, BOOLEAN showError)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pID);
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


BOOL EnumProc()
{
	HMODULE hNtdll = ::LoadLibrary(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQuerySystemInformation = (NtQuerySystemInformation_t)::GetProcAddress(hNtdll, "NtQuerySystemInformation");

		::FreeLibrary(hNtdll);

		HANDLE hHeap = ::GetProcessHeap();
		PVOID buffer = NULL;
		ULONG bufferSize = 0x10000;
		ULONG returnLen = 0;
		NTSTATUS status;

		for (;;) {

			if (buffer) {
				::HeapFree(hHeap, 0, buffer);
				buffer = NULL;
			}

			buffer = ::HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
			if (!buffer) return FALSE;

			status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLen);
			if (status == STATUS_SUCCESS) break;

			else if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
				if (returnLen > bufferSize)
					bufferSize = (returnLen + (1 << 12));
				else bufferSize *= 2;
			}

			else {
				if (buffer) ::HeapFree(hHeap, 0, buffer);
				return FALSE;
			}
		}

		auto process = (PSYSTEM_PROCESS_INFORMATION)buffer;
		int processCount = 0;

		WCHAR filename[512] = {0};
		WCHAR cmdline[512]  = {0};

		for (;;processCount++) {

			GetProcessFilePath(HandleToULong(process->UniqueProcessId), filename);
			GetProcessCommandLine(HandleToULong(process->UniqueProcessId), cmdline);

			if (process->NextEntryOffset == 0) break;
			process = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)process + process->NextEntryOffset);
		}
		return TRUE;
	}
	return FALSE;
}


BOOL GetProcessFilePath(DWORD pID, LPWSTR filename)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hNtdll, "NtQueryInformationProcess");

		::FreeLibrary(hNtdll);

		HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, FALSE);
		if (hProcess != NULL) {

			ULONG retLen;
			NTSTATUS res = NtQueryInformationProcess(hProcess, ProcessImageFileName, nullptr, 0, &retLen);

			PUNICODE_STRING buffer = (PUNICODE_STRING)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, retLen);

			if (buffer) {

				res = NtQueryInformationProcess(hProcess, ProcessImageFileName, buffer, retLen, &retLen);
				wcsncpy_s(filename, buffer->Length / sizeof(WCHAR) + 1, buffer->Buffer, buffer->Length / sizeof(WCHAR));

				return TRUE;
			}
		}
	}
	return FALSE;
}


BOOL GetProcessCommandLine(DWORD pID, LPWSTR cmdline)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hNtdll, "NtQueryInformationProcess");

		::FreeLibrary(hNtdll);

		HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, FALSE);
		if (hProcess != NULL) {

			ULONG retLen;
			NTSTATUS res = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, nullptr, 0, &retLen);

			PUNICODE_STRING buffer = (PUNICODE_STRING)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, retLen);

			if (buffer) {

				res = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, buffer, retLen, &retLen);
				wcsncpy_s(cmdline, buffer->Length / sizeof(WCHAR) + 1, buffer->Buffer, buffer->Length / sizeof(WCHAR));

				return TRUE;
			}
		}
	}
	return FALSE;
}


BOOL GetProcessExtendedBasicInformation(DWORD pID, PPROCESS_EXTENDED_BASIC_INFORMATION pbi, SIZE_T spbi)
{
	HMODULE hNtdll = ::LoadLibraryW(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hNtdll, "NtQueryInformationProcess");

		::FreeLibrary(hNtdll);

		HANDLE hProcess = OpenProcessWithQueryLimitedInformation(pID, TRUE);
		if (hProcess != NULL) {
			ULONG nRetLen;

			pbi->Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

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
		auto NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hNtdll, "NtQueryInformationProcess");

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
		auto NtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(ntdll, "NtQueryInformationProcess");

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


BOOL GetProcessMitigation(DWORD pID, PMITIGATION m)
{
	HANDLE hProcess = OpenProcessWithQueryInformation(pID, FALSE);

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

	SecureCloseHandle(hProcess);

	return TRUE;
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

			::ConvertSidToStringSidW(tUser->User.Sid, (LPWSTR*)&stringSid);
			::LookupAccountSidW(nullptr, tUser->User.Sid, pUserInfo->UserName, &userNameSize, pUserInfo->DomainName, &domainNameSize, &use);

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
		::IsWow64Process(hProcess, &res);

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