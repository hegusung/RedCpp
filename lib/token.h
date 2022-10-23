#ifndef TOKEN_HEADER
#define TOKEN_HEADER

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <psapi.h>
#include <ntsecapi.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <list>
#include <userenv.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Userenv.lib")

class Privilege
{
public:
	Privilege(std::string name, bool enabled, bool enabled_by_default, bool removed, bool used_for_access);
	std::string name;
	bool enabled;
	bool enabled_by_default;
	bool removed;
	bool used_for_access;
};

class Token
{
public:
	Token(HANDLE token_handle);
	~Token();
	int getTokenType(int* token_type, int* impersonation_level, ULONG* session_logon_type);
	int getTokenUser(char** username, char** domain);
	std::list<Privilege>* getTokenPrivs();
	int enablePrivilege(const char* privilege_name);
	int impersonate();
	int loadUserProfile();
	int createProcess(const wchar_t* application);
	Token* duplicate();
private:
	HANDLE hToken;
};

Token* getCurrentToken(int desiredAccess);
Token* getTokenByPID(int pid);
Token* createToken(const char* domain, const char* username, const char* password);

#endif