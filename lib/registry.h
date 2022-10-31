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

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

class RegEntry
{
public:
	RegEntry(const char* name, const char* value);
	std::string name;
	std::string value;
};

class Registry
{
public:
	Registry();
	~Registry();
	bool get_path(const char* reg_path, HKEY* root, const char** reg_subpath);
	std::list<RegEntry>* list_registry_keys(const char* reg_path);
	bool set_registry(const char* reg_path, const char* name, const char* value);
	bool remove_registry(const char* reg_path, const char* name);
private:

};

#endif
