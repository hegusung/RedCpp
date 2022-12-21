/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "winrm.h"

WinRM::WinRM()
{
    init_done = false;

    memset(&async, 0, sizeof(async));
}

WinRM::~WinRM()
{
}

bool WinRM::init(const wchar_t* hostname, const wchar_t* username, const wchar_t* password, bool ssl)
{
    dwError = WSManInitialize((DWORD)WSMAN_FLAG_REQUESTED_API_VERSION_1_1, &this->hWSMan);
    if (dwError != 0)
    {
#ifdef DEBUG
        printf("WSManInitialize failure: %x\n", dwError);
#endif
        return false;
    }

    WSMAN_AUTHENTICATION_CREDENTIALS authCreds;
    authCreds.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    authCreds.userAccount.username = username;
    authCreds.userAccount.password = password;

    std::wstring connection;
    if(ssl)
        connection = std::wstring(L"https://") + hostname + L":5986";
    else
        connection = std::wstring(L"http://") + hostname + L":5985";
    dwError = WSManCreateSession(this->hWSMan, connection.c_str(), 0, &authCreds, NULL, &this->hSession);
    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManCreateSession failed: %x\n", dwError);
#endif
        return false;
    }

    WSManSessionOption option = WSMAN_OPTION_DEFAULT_OPERATION_TIMEOUTMS;
    WSMAN_DATA data;
    data.type = WSMAN_DATA_TYPE_DWORD;
    data.number = 60000;
    dwError = WSManSetSessionOption(hSession, option, &data);
    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManSetSessionOption failed: %x\n", dwError);
#endif
        return false;
    }

    hEvent = CreateEventA(0, FALSE, FALSE, NULL);
    if (NULL == hEvent)
    {
#ifdef DEBUG
        dwError = GetLastError();
        wprintf(L"CreateEvent failed: %x\n", dwError);
#endif
        return false;
    }
    async.operationContext = this;
    async.completionFunction = (WSMAN_SHELL_COMPLETION_FUNCTION)&WSManShellCompletionFunction;


    hReceiveEvent = CreateEventA(0, FALSE, FALSE, NULL);
    if (NULL == hReceiveEvent)
    {
#ifdef DEBUG
        dwError = GetLastError();
        wprintf(L"CreateEvent failed: %x\n", dwError);
#endif
        return false;
    }
    receiveAsync.operationContext = this;
    receiveAsync.completionFunction = (WSMAN_SHELL_COMPLETION_FUNCTION)&ReceiveCallback;

    init_done = true;

    return true;
}

std::wstring WinRM::execute(std::wstring command)
{
    output = L"";

    std::wstring resourceUri = L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

    WSManCreateShell(hSession, 0, resourceUri.c_str(), NULL, NULL, NULL, &async, &hShell);

    dwError = WaitForSingleObject(hEvent, INFINITE);
    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManCreateShell failed: %x\n", dwError);
#endif
        this->output += L"WSManCreateShell failed: " + std::to_wstring(dwError);
        return this->output;
    }
    
    WSManRunShellCommand(hShell, 0, command.c_str(), NULL, NULL, &async, &hCommand);

    WaitForSingleObject(hEvent, INFINITE);
    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManRunShellCommand failed: %x\n", dwError);
#endif
        this->output += L"WSManRunShellCommand failed: " + std::to_wstring(dwError);
        return this->output;
    }

    WSMAN_OPERATION_HANDLE receiveOp = NULL;

    WSManReceiveShellOutput(hShell, hCommand, 0, NULL, &receiveAsync, &receiveOp);

    WaitForSingleObject(hReceiveEvent, INFINITE);
    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManReceiveShellOutput failed: %x\n", dwError);
#endif
        this->output += L"WSManReceiveShellOutput failed: " + std::to_wstring(dwError);
        return this->output;
    }

    dwError = WSManCloseOperation(receiveOp, 0);

    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManCloseOperation failed: %x\n", dwReceieveError);
#endif
        this->output += L"WSManCloseOperation failed: " + std::to_wstring(dwError);
        return this->output;
    }

    return this->output;
}

void WinRM::cleanup()
{

    if (NULL != hCommand)
    {
        WSManCloseCommand(hCommand, 0, &async);

        WaitForSingleObject(hEvent, INFINITE);
        if (dwError != 0)
        {
#ifdef DEBUG
            wprintf(L"WSManCloseCommand failed: %x\n", dwError);
#endif
        }
        else
        {
            hCommand = NULL;
        }
    }

    if (NULL != hShell)
    {
        WSManCloseShell(hShell, 0, &async);
        WaitForSingleObject(hEvent, INFINITE);
        if (NO_ERROR != dwError)
        {
#ifdef DEBUG
            wprintf(L"WSManCloseShell failed: %x\n", dwError);
#endif
        }
        else
        {
            hShell = NULL;
        }
    }

    dwError = WSManCloseSession(hSession, 0);
    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManCloseSession failed: %x\n", dwError);
#endif
    }

    dwError = WSManDeinitialize(hWSMan, 0);
    if (dwError != 0)
    {
#ifdef DEBUG
        wprintf(L"WSManDeinitialize failed: %x\n", dwError);
#endif
    }

    if (NULL != hEvent)
    {
        CloseHandle(hEvent);
        hEvent = NULL;
    }
    if (NULL != hReceiveEvent)
    {
        CloseHandle(hReceiveEvent);
        hReceiveEvent = NULL;
    }

    init_done = false;

}

void CALLBACK WinRM::WSManShellCompletionFunction
(
    __in_opt PVOID operationContext,
    DWORD flags,
    __in WSMAN_ERROR* error,
    __in WSMAN_SHELL_HANDLE shell,
    __in_opt WSMAN_COMMAND_HANDLE command,
    __in_opt WSMAN_OPERATION_HANDLE operationHandle,
    __in_opt WSMAN_RECEIVE_DATA_RESULT* data
)
{
    if (operationContext)
    {
        WinRM* context = reinterpret_cast<WinRM*>(operationContext);
        context->m_WSManShellCompletionFunction(flags, error, shell, command, operationHandle, data);
    }
}

void CALLBACK WinRM::m_WSManShellCompletionFunction
(
    DWORD flags,
    __in WSMAN_ERROR* error,
    __in WSMAN_SHELL_HANDLE shell,
    __in_opt WSMAN_COMMAND_HANDLE command,
    __in_opt WSMAN_OPERATION_HANDLE operationHandle,
    __in_opt WSMAN_RECEIVE_DATA_RESULT* data
)
{
    if (error && 0 != error->code)
    {
        dwError = error->code;
        //wprintf(error->errorDetail);

        this->output += L"ERROR: \n" + std::wstring(error->errorDetail) + L"\n";
    }
    SetEvent(hEvent);
}

void CALLBACK WinRM::ReceiveCallback
(
    __in_opt PVOID operationContext,
    DWORD flags,
    __in WSMAN_ERROR* error,
    __in WSMAN_SHELL_HANDLE shell,
    __in_opt WSMAN_COMMAND_HANDLE command,
    __in_opt WSMAN_OPERATION_HANDLE operationHandle,
    __in_opt WSMAN_RECEIVE_DATA_RESULT* data
)
{
    if (operationContext)
    {
        WinRM* context = reinterpret_cast<WinRM*>(operationContext);
        context->m_ReceiveCallback(flags, error, shell, command, operationHandle, data);
    }
}
void CALLBACK WinRM::m_ReceiveCallback
(
    DWORD flags,
    __in WSMAN_ERROR* error,
    __in WSMAN_SHELL_HANDLE shell,
    __in_opt WSMAN_COMMAND_HANDLE command,
    __in_opt WSMAN_OPERATION_HANDLE operationHandle,
    __in_opt WSMAN_RECEIVE_DATA_RESULT* data
)
{
    if (error && 0 != error->code)
    {
        dwReceieveError = error->code;
        //wprintf(error->errorDetail);

        this->output += L"ERROR: \n" + std::wstring(error->errorDetail) + L"\n";
    }

    //printf("Type: %d\n", data->streamData.type);

    if (data && data->streamData.type == WSMAN_DATA_TYPE_BINARY && data->streamData.binaryData.dataLength)
    {
        //HANDLE hFile = ((0 == _wcsicmp(data->streamId, WSMAN_STREAM_ID_STDERR)) ? GetStdHandle(STD_ERROR_HANDLE) : GetStdHandle(STD_OUTPUT_HANDLE));

        //DWORD t_BufferWriteLength = 0;

        //WriteFile(hFile, data->streamData.binaryData.data, data->streamData.binaryData.dataLength, &t_BufferWriteLength, NULL);

        //printf("Yeah: %s\n", data->streamData.binaryData.data);

        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::wstring w_str = converter.from_bytes((char*)data->streamData.binaryData.data);

        this->output += w_str;
    }

    if ((error && 0 != error->code) || (data && data->commandState && wcscmp(data->commandState, WSMAN_COMMAND_STATE_DONE) == 0))
    {
        SetEvent(hReceiveEvent);
    }
}