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

typedef std::vector<char> vectByte;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

class SystemInfo
{
public:
	SystemInfo(WORD wProcessorArchitecture, DWORD dwNumberOfProcessors, DWORD dwMajorVersion, DWORD dwMinorVersion, DWORD dwBuildNumber, DWORD wProductType);
	std::string proc_arch;
	unsigned int nb_procs;
	std::string win_version;
};

class Application
{
public:
	Application(char* application, char* version);
	Application(std::string application, std::string version);
	std::string name;
	std::string version;
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
	SystemInfo getSystemInfo();
	std::list<Application> getApplications();
	std::list<RDPServer> getRDPServers();
	// registry
	std::list<std::string> listSubkeys(const char* reg_path);
	std::string getStringRegKey(HKEY hKey, const char* valueName);
	// Screenshot
	vectByte screenshot();
};

void image_to_buffer_png(const CImage &image, vectByte &buf);