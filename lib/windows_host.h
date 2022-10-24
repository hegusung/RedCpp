/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#pragma once

#ifndef WINDOWS_HOST_HEADER
#define WINDOWS_HOST_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <Windows.h>
#include <lm.h>
#include <locale>
#include <codecvt>
#include <Wbemidl.h>
#include <comdef.h>
#include <ctime>
#include <chrono>
#include <shlwapi.h>

#include "../lib/security.h"
#include "../lib/wmi.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Mpr.lib")

class Share
{
public:
	Share(std::wstring name, std::wstring local_path, std::wstring comment, SecurityDescriptor* security_descriptor);
	~Share();
	std::wstring name;
	std::wstring local_path;
	std::wstring comment;
	SecurityDescriptor* security_descriptor;
};

class SystemInfo
{
public:
	SystemInfo(std::wstring computername, std::wstring os_version, std::wstring langroup, std::wstring lanroot);
	~SystemInfo();
	std::wstring computername;
	std::wstring os_version;
	std::wstring langroup;
	std::wstring lanroot;
};

#define SVC_SHARE "IPC$"
#define ADMIN_SHARE "ADMIN$"

class WindowsHost
{
public:
	WindowsHost(const char* ip);
	~WindowsHost();
	// Authentication
	DWORD auth(const char* ressource, const char* username, const char* password);
	DWORD deauth(const char* ressource);
	// Information gathering
	SystemInfo* getSystemInfo();
	std::list<Share>* shares();
	// RCE methods
	int RCE_wmi(const char* command);
	int RCE_wmi(const char* command, const char* username, const char* password);
	int RCE_wmi_output(char** output, const char* command, const char* username, const char* password, size_t timeout_s);
	int RCE_wmi_output(char** output, const char* command, size_t timeout_s);
	int RCE_svc(const char* svc_name, const char* command, BOOL delete_service, size_t delete_after_ms);
	int RCE_svc_output(char** output, const char* command, const char* username, const char* password, size_t timeout_s);
	int RCE_svc_output(char** output, const char* command, size_t timeout_s);
	// utils
	int write_remote_file(char* data, size_t data_size, const char* share_name, char* path);
	int get_remote_file(char** output, const char* share_name, char* path, BOOL delete_file);
	bool remote_file_exists(const char* share_name, char* path);
	bool delete_remote_file(const char* share_name, char* path);
private:
	std::string ip;
};

void init_random();
void gen_random(char* s, const int len);

#endif