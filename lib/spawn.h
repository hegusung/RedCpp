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

#include "process_hollowing.h"
#include "reflective_injection.h"

class Spawn
{
public:
	Spawn();
	~Spawn();
	bool start_exe(const char* exe_path, const char* args, unsigned int ppid = NULL);
	bool start_process_hollowing(const char* exe_path, LPVOID exe_data, unsigned int ppid = NULL);
	bool reflective_injection(unsigned int pid, LPVOID exe_data, size_t exe_data_size);
private:
	PPROC_THREAD_ATTRIBUTE_LIST get_ppid_attribute_list(unsigned int ppid, HANDLE* handle);
	BOOL CurrentProcessAdjustToken();
};

#endif
