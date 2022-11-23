/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <Shlwapi.h>
#include <atlimage.h>
#include <memory>
#include <gdiplus.h>
#include <vector>
#include <windows.h>
#include <olectl.h> 
#include <Wbemidl.h>
#include <comdef.h>
#include <tlhelp32.h>

# pragma comment(lib, "wbemuuid.lib")

typedef std::vector<char> vectByte;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

class SystemInfo
{
public:
	SystemInfo(std::wstring os_name, std::wstring os_arch, std::wstring install_date, std::wstring last_boot_date);
	std::wstring os_name;
	std::wstring os_arch;
	std::wstring install_date;
	std::wstring last_boot_date;
};

class Application
{
public:
	Application(char* application, char* version);
	Application(std::string application, std::string version);
	std::string name;
	std::string version;
};

class Process
{
public:
	Process(const char* exe_name, const char* exe_path, unsigned int pid, unsigned int parent_pid, const char* image_type);
	std::string exe_name;
	std::string exe_path;
	unsigned int pid;
	unsigned int parent_pid;
	std::string image_type;
};

class RDPServer
{
public:
	RDPServer(std::string username, std::string server);
	std::string username;
	std::string server;
};

class Localhost
{
public:
	Localhost();
	~Localhost();
	SystemInfo* get_system_info();
	std::list<Process> list_processes();
	std::list<Application> list_applications();
	std::list<RDPServer> list_rdp_servers();
	// registry
	std::list<std::string>* listSubKeys(const char* reg_path);
	std::string getStringRegKey(HKEY hKey, const char* valueName);
	// Screenshot
	vectByte screenshot();
};

void image_to_buffer_png(const CImage &image, vectByte &buf);

bool initializeCom();
bool setUpWBEM(IWbemLocator*& wbemLocator, IWbemServices*& wbemServices);