/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef PROCESS_HEADER
#define PROCESS_HEADER


#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <psapi.h>
#include <ntsecapi.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <list>
#include "token.h"

#pragma comment(lib, "psapi.lib")

class Process
{
public:
	Process(HANDLE hProcess, int pid);
	~Process();
	Token* getToken();
	Token* getToken(int desired_access);
	std::string* getProcessPath();
	std::string* getProcessName();
	int getPID();
private:
	HANDLE hProcess;
	int pid;
};

Process* getProcessByPID(int pid);
Process* getProcessByPID(int pid, int desired_access);
std::list<Process*>* enumerateProcesses(int desired_access);
int createProcess(const wchar_t* domain, const wchar_t* username, const wchar_t* password, const wchar_t* application);

#endif