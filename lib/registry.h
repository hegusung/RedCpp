/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef REGISTRY_HEADER
#define REGISTRY_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <Windows.h>
#include <tchar.h>
#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

class RegEntry
{
public:
	RegEntry(const char* name, const char* type, std::string value);
	std::string name;
	std::string type;
	std::string value;
};

class COM_object
{
public:
	COM_object(const char* name, const char* clsid);
	std::string name;
	std::string clsid;
};

class Registry
{
public:
	Registry();
	~Registry();
	bool get_path(const char* reg_path, HKEY* root, const char** reg_subpath);
	std::list<std::string>* list_registry_subkeys(const char* reg_path);
	std::list<RegEntry>* list_registry_entries(const char* reg_path);
	bool set_entry_sz(const char* reg_path, const char* name, const char* value);
	bool set_entry_dword(const char* reg_path, const char* name, DWORD value);
	bool set_entry_multi_sz(const char* reg_path, const char* name, const char* value);
	bool remove_entry(const char* reg_path, const char* name);
	bool delete_key(const char* reg_path);
	std::list<COM_object>* list_com();
private:

};

#endif
