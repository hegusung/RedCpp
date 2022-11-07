/*
* Github: https://github.com/adamhlt/Process-Hollowing
*/

#ifndef PROCESS_HOLLOWING_HEADER
#define PROCESS_HOLLOWING_HEADER

#include <Windows.h>
#include <cstdio>
#include <winternl.h>

// Structure to store the address process infromation.
struct ProcessAddressInformation
{
	LPVOID lpProcessPEBAddress;
	LPVOID lpProcessImageBaseAddress;
};

//Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

BOOL IsValidPE(const LPVOID lpImage);
BOOL IsPE32(const LPVOID lpImage);
ProcessAddressInformation GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI);
ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI);
DWORD GetSubsytem32(const LPVOID lpImage);
DWORD GetSubsytem64(const LPVOID lpImage);
DWORD GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress);
DWORD GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress);
void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI);
void CleanProcess(const LPPROCESS_INFORMATION lpPI);
BOOL HasRelocation32(const LPVOID lpImage);
BOOL HasRelocation64(const LPVOID lpImage);
IMAGE_DATA_DIRECTORY GetRelocAddress32(const LPVOID lpImage);
IMAGE_DATA_DIRECTORY GetRelocAddress64(const LPVOID lpImage);
BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
BOOL RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);
BOOL RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage);

#endif
