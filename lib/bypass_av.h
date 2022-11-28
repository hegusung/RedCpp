/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

/*
* Possible techniques
*  - METHOD_NTDLL ; Calls ntdll directly
*  - METHOD_SYSCALL_EMBEDDED ; Syswhisper Embedded method
*  - METHOD_SYSCALL_JUMPER ; Syswhisper Jumper method
*  - METHOD_SYSCALL_JUMPER_RANDOMIZED ; Syswhisper Jumper_randomized method
*  - METHOD_SYSCALL_EGG_HUNTER ; Syswhisper Egg hunter method
*/
#define METHOD_SYSCALL_JUMPER_RANDOMIZED

#ifndef BYPASS_AV_HEADER
#define BYPASS_AV_HEADER

#include <stdio.h>
#include <Windows.h>
#include <psapi.h>

#if defined(METHOD_NTDLL)
#include "win_nt.h"
#elif defined(METHOD_SYSCALL_EMBEDDED)
#include "../syswhisper/syscalls_embedded.h"
#elif defined(METHOD_SYSCALL_JUMPER)
#include "../syswhisper/syscalls_jumper.h"
#elif defined(METHOD_SYSCALL_JUMPER_RANDOMIZED)
#include "../syswhisper/syscalls_jumper_randomized.h"
#elif defined(METHOD_SYSCALL_EGG_HUNTER)
#include "../syswhisper/syscalls_egg_hunter.h"
#endif

#include <iostream>
#include <iomanip>

#define FILE_OPEN 0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define OBJ_CASE_INSENSITIVE 0x00000040

#define InitializeObjectAttributes(p, n, a, r, s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = r; \
(p)->Attributes = a; \
(p)->ObjectName = n; \
(p)->SecurityDescriptor = s; \
(p)->SecurityQualityOfService = NULL; \
}

FORCEINLINE VOID RtlInitUnicodeString(
    _Out_ PDUNICODE_STRING DestinationString,
    _In_opt_ PWSTR SourceString
)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(WCHAR);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = SourceString;
}

class Bypass_EDR
{
public:
	Bypass_EDR();
	~Bypass_EDR();

	// API to access DLL files
	HANDLE CreateFileW(LPWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes);
    NTSTATUS ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead);
	BOOL CloseHandle(HANDLE hObject);

    // Complete unhooking
    BOOL check_dll(const char* dll_name, const char* ntdll_data);
    BOOL unhook_dll(const char* dll_name, const char* ntdll_data);

};

#endif
