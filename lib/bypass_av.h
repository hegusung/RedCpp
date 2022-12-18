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
#define METHOD_NTDLL

#ifndef BYPASS_AV_HEADER
#define BYPASS_AV_HEADER

#include <stdio.h>
#include <Windows.h>
#include <psapi.h>
#include <map>
#include <list>
#include <string>
#include <tlhelp32.h>
#include "MemoryModule.h"

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

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    DUNICODE_STRING FullDllName;
    DUNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

class DLL
{
public:
    DLL(char* name, BYTE* address);
    std::string name;
    BYTE* address;
};

class Bypass_EDR
{
public:
	Bypass_EDR();
	~Bypass_EDR();

	// API to access DLL files
	HANDLE CreateFileW(LPWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes);
    NTSTATUS ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead);
	BOOL CloseHandle(HANDLE hObject);
    BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);

    // Source: https://medium.com/@omribaso/this-is-how-i-bypassed-almost-every-edr-6e9792cf6c44
    // GetModuleFromPEB = LoadLibraryA
    void* GetModuleFromPEB(const wchar_t* wModuleName);
    // GetAPIFromPEBModule = GetProcAddress
    uintptr_t GetAPIFromPEBModule(void* hModule, const char* wAPIName);

    // Complete unhooking
    BOOL check_dll(const char* dll_name, const char* ntdll_data);
    BOOL unhook_dll(const char* dll_name, const char* ntdll_data);

    // Disable security features, source: https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/
    BOOL disable_etw();

    // Memory module, load dll from memory
    bool load_dll(const char* dll_name, const char* dll_data, size_t dll_size);
    bool dll_exists(const char* dll_name);
    void* get_func(const char* dll_name, const char* func_name);

    std::list<DLL> list_loaded_dlls();

    std::list<std::string> check_hook_jmp(HMODULE hDll);
    std::list<std::string>* check_hook_diff(const wchar_t* dll_path);
private:
    std::map<std::string, HMEMORYMODULE> module_map;
};

#endif
