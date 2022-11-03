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