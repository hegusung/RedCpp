/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef SPAWN_HEADER
#define SPAWN_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <Windows.h>

class Spawn
{
public:
	Spawn();
	~Spawn();
	bool start_exe(const char* exe_path, const char* args, unsigned int ppid = NULL);
private:
	PPROC_THREAD_ATTRIBUTE_LIST get_ppid_attribute_list(unsigned int ppid, HANDLE* handle);
	BOOL CurrentProcessAdjustToken();
};

#endif
