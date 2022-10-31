/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef NET_HEADER
#define NET_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <Windows.h>
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

class Net
{
public:
	Net();
	~Net();
	std::list<std::wstring> get_local_groups(const char* user);
	std::list<std::wstring> get_global_groups(const char* user);
private:

};

#endif
