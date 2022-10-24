/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "process.h"

//#define DEBUG

Process::Process(HANDLE hProcess, int pid)
{
	this->hProcess = hProcess;
	this->pid = pid;
}

Process::~Process()
{
	CloseHandle(this->hProcess);
}

Token* Process::getToken(int desired_access)
{
	HANDLE hToken;
	if (!OpenProcessToken(this->hProcess, desired_access, &hToken))
	{
		#ifdef DEBUG
		printf("Unable to get current token: %d\n", GetLastError());
		#endif
		return NULL;
	}

	Token* token = new Token(hToken);

	return token;
}

Token* Process::getToken()
{
	return this->getToken(TOKEN_READ);
}

std::string* Process::getProcessPath()
{
	char path_char[MAX_PATH];

    if (!GetModuleFileNameEx(this->hProcess, 0, path_char, MAX_PATH))
    {
		return NULL;
    }

	std::string* path = new std::string(path_char);

	return path;
}

std::string* Process::getProcessName()
{
	char name_char[MAX_PATH];
	HMODULE hMod;
	DWORD cbNeeded;

	if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
	{
		GetModuleBaseName( hProcess, hMod, name_char, MAX_PATH );

		std::string* name = new std::string(name_char);

		return name;
	}
	else
	{
		return NULL;
	}
}

int Process::getPID()
{
	return this->pid;
}

Process* getProcessByPID(int pid, int desired_access)
{
	HANDLE hProcess = OpenProcess( desired_access, FALSE, pid);
	if(hProcess == NULL)
	{
		#ifdef DEBUG
		printf("Unable to open process: %d\n", GetLastError());
		#endif
		return NULL;
	}

	Process* process = new Process(hProcess, pid);

	return process;
}

Process* getProcessByPID(int pid)
{
	return getProcessByPID(pid, PROCESS_QUERY_INFORMATION |PROCESS_VM_READ);

}

std::list<Process*>* enumerateProcesses(int desired_access)
{
	SetLastError(0);
	// Get the list of process identifiers.
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
#ifdef DEBUG
		printf("EnumProcesses error: %d\n", GetLastError());
#endif
        return NULL;
    }

	std::list<Process*>* process_list = new std::list<Process*>();

    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.
    for ( i = 0; i < cProcesses; i++ )
    {
        if( aProcesses[i] != 0 )
        {
			// Get a handle to the process.

			HANDLE hProcess = OpenProcess(desired_access, FALSE, aProcesses[i]);

			if(hProcess == NULL)
			{
				#ifdef DEBUG
				printf("Unable to open process %d: %d\n", aProcesses[i], GetLastError());
				#endif
				continue;
			}

			Process* proc = new Process(hProcess, aProcesses[i]);

			proc->getProcessName();

			process_list->push_back(proc);
        }
    }

	return process_list;
}

int createProcess(const wchar_t* domain, const wchar_t* username, const wchar_t* password, const wchar_t* application)
{
	STARTUPINFOW si = {};
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessWithLogonW(username, domain, password, LOGON_WITH_PROFILE, application, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		return GetLastError();
	}

	return 0;
}