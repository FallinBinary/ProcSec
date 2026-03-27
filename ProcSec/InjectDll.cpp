#include "InjectDll.h"

BOOL DllInjection(DWORD dPid)
{
	WCHAR sDllPath[MAX_PATH] = { 0 };
	OpenDll(sDllPath);

	HANDLE hProcess = ::OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, dPid);
	if (hProcess == NULL) {
		if (::GetLastError() == ERROR_ACCESS_DENIED)
			::MessageBoxW(nullptr, L"OpenProcess Failed: Access is denied.", L"Process Security", MB_OK | MB_ICONERROR);
		else
			ShowErrorWithLastError(L"OpenProcess");
		return FALSE;
	}

	RtlCreateUserThread_t pRtlCreateUserThread = nullptr;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	HMODULE hNtdll = ::GetModuleHandleW(L"ntdll.dll");
	HMODULE hKernel32 = ::GetModuleHandleW(L"kernel32.dll");
	if (hNtdll && hKernel32) {
		pRtlCreateUserThread = (RtlCreateUserThread_t)::GetProcAddress(hNtdll, "RtlCreateUserThread");

		::FreeLibrary(hNtdll);

		LPVOID lpMem = ::VirtualAllocEx(hProcess, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpMem == nullptr) {
			ShowErrorWithLastError(L"VirtualAllocEx");
			SecureCloseHandle(hProcess);
			::FreeLibrary(hKernel32);
			return FALSE;
		}

		::WriteProcessMemory(hProcess, lpMem, sDllPath, MAX_PATH, nullptr);

		pRtlCreateUserThread(hProcess, nullptr, FALSE, 0, 0, 0, ::GetProcAddress(hKernel32, "LoadLibraryW"), lpMem, &hThread, &cid);
		if (hThread == nullptr)
			::MessageBoxW(nullptr, L"Injection failed.", L"Process Security", MB_OK | MB_ICONERROR);
		else
			::MessageBoxW(nullptr, L"Injection successfully done.", L"Process Security", MB_OK | MB_ICONINFORMATION);
	
		::FreeLibrary(hKernel32);
	}

	SecureCloseHandle(hProcess);
	return TRUE;
}


BOOL OpenDll(LPWSTR lpDllPath)
{
	//WCHAR fileName[MAX_PATH];
	OPENFILENAME ofn = { 0 };

	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = nullptr;
	ofn.lpstrFile = lpDllPath;
	ofn.lpstrFile[0] = L'\0';
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"Dynamic link library (*.dll)\0*.dll\0";
	ofn.nFilterIndex = 1;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

	if (!::GetOpenFileNameW(&ofn))
		return FALSE;

	return TRUE;
}
