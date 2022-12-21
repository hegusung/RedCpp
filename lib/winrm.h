/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

// Source: https://github.com/mez-0/winrmdll/blob/main/src/winrm.cpp

#ifndef WINRM_HEADER
#define WINRM_HEADER

#include <windows.h>

#define WSMAN_API_VERSION_1_1

#include <string>
#include <wsman.h>
#include <wsmandisp.h>

#include <locale>
#include <codecvt>


#pragma comment(lib, "wsmsvc.lib")

class WinRM
{
public:
	WinRM();
	~WinRM();
	bool init(const wchar_t* hostname, const wchar_t* username, const wchar_t* password, bool ssl=false);
	std::wstring execute(std::wstring command);
	void cleanup();

    static void CALLBACK WSManShellCompletionFunction
    (
        __in_opt PVOID operationContext,
        DWORD flags,
        __in WSMAN_ERROR* error,
        __in WSMAN_SHELL_HANDLE shell,
        __in_opt WSMAN_COMMAND_HANDLE command,
        __in_opt WSMAN_OPERATION_HANDLE operationHandle,
        __in_opt WSMAN_RECEIVE_DATA_RESULT* data
    );

    void CALLBACK m_WSManShellCompletionFunction
    (
        DWORD flags,
        __in WSMAN_ERROR* error,
        __in WSMAN_SHELL_HANDLE shell,
        __in_opt WSMAN_COMMAND_HANDLE command,
        __in_opt WSMAN_OPERATION_HANDLE operationHandle,
        __in_opt WSMAN_RECEIVE_DATA_RESULT* data
    );

    static void CALLBACK ReceiveCallback
    (
        __in_opt PVOID operationContext,
        DWORD flags,
        __in WSMAN_ERROR* error,
        __in WSMAN_SHELL_HANDLE shell,
        __in_opt WSMAN_COMMAND_HANDLE command,
        __in_opt WSMAN_OPERATION_HANDLE operationHandle,
        __in_opt WSMAN_RECEIVE_DATA_RESULT* data
    );
    void CALLBACK m_ReceiveCallback
    (
        DWORD flags,
        __in WSMAN_ERROR* error,
        __in WSMAN_SHELL_HANDLE shell,
        __in_opt WSMAN_COMMAND_HANDLE command,
        __in_opt WSMAN_OPERATION_HANDLE operationHandle,
        __in_opt WSMAN_RECEIVE_DATA_RESULT* data
    );
private:
	bool init_done;
	WSMAN_API_HANDLE hWSMan;
	WSMAN_SESSION_HANDLE hSession;
	WSMAN_SHELL_ASYNC async;
	HANDLE hEvent;
	WSMAN_SHELL_ASYNC receiveAsync;
	HANDLE hReceiveEvent;
	DWORD dwReceieveError;
	DWORD dwError;

	WSMAN_COMMAND_HANDLE hCommand;
	WSMAN_SHELL_HANDLE hShell;

    std::wstring output;
};


#endif
