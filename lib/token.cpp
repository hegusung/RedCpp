/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "token.h"

//#define DEBUG

Token* getCurrentToken(int desiredAccess)
{
	HANDLE hToken;

	if (!OpenThreadToken(GetCurrentThread(), desiredAccess, TRUE, &hToken))
	{
		if(GetLastError() == ERROR_NO_TOKEN)
		{
			#ifdef DEBUG
			printf("No token on thread, try to get process token then\n", GetLastError());
			#endif

			if (!OpenProcessToken(GetCurrentProcess(), desiredAccess, &hToken))
			{
				#ifdef DEBUG
				printf("Unable to get current process token: %d\n", GetLastError());
				#endif
				return NULL;
			}
		}
		else
		{
			#ifdef DEBUG
			printf("Unable to get current thread token: %d\n", GetLastError());
			#endif
			return NULL;
		}
	}

	Token* token = new Token(hToken);

	return token;
}

Token* getTokenByPID(int pid)
{
	HANDLE hProcess;
	HANDLE hToken;

	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE, pid);
	if(hProcess == NULL)
	{
		#ifdef DEBUG
		printf("Unable to open process: %d\n", GetLastError());
		#endif
		return NULL;
	}

	if (!OpenProcessToken(hProcess, TOKEN_READ, &hToken))
	{
		#ifdef DEBUG
		printf("Unable to get current token: %d\n", GetLastError());
		#endif
		return NULL;
	}

	Token* token = new Token(hToken);

	return token;
}

Token::Token(HANDLE hToken)
{
	this->hToken = hToken;
}

Token::~Token()
{
	CloseHandle(this->hToken);
}

int Token::getTokenType(int* token_type, int* impersonation_level, ULONG* session_logon_type)
{
	DWORD n;
	BOOL success;
	TOKEN_STATISTICS* token_stats;
	SECURITY_LOGON_SESSION_DATA* logon_session_data;

	#ifdef DEBUG
	printf("Handle: %d\n", hToken);
	#endif

	if (!GetTokenInformation(this->hToken, TokenStatistics, 0, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		#ifdef DEBUG
		printf("\tUnable to get token informations: %d\n", GetLastError());
		#endif
		return GetLastError();
	}

	token_stats = (TOKEN_STATISTICS*)malloc(n);

	if (!GetTokenInformation(this->hToken, TokenStatistics, (PVOID)token_stats, n, &n))
	{
		#ifdef DEBUG
		printf("\tUnable to get token informations: %d\n", GetLastError());
		#endif
		free(token_stats);
		return GetLastError();
	}

	*token_type = token_stats->TokenType;
	*impersonation_level = token_stats->TokenType;

	//#ifdef DEBUG
	if(token_stats->TokenType == TokenPrimary)
	{
		printf("\tProcess token (can be used to authenticate remotely)\n");
	}
	else if(token_stats->TokenType == TokenImpersonation)
	{
		printf("\tThread token\n");
		if(token_stats->ImpersonationLevel == SecurityAnonymous)
		{
			printf("\tImpersonation level: SecurityAnonymous\n");
		}
		else if(token_stats->ImpersonationLevel == SecurityIdentification)
		{
			printf("\tImpersonation level: SecurityIdentification\n");
		}
		else if(token_stats->ImpersonationLevel == SecurityImpersonation)
		{
			printf("\tImpersonation level: SecurityImpersonation (can be used to authenticate remotely)\n");
		}
		else if(token_stats->ImpersonationLevel == SecurityDelegation)
		{
			printf("\tImpersonation level: SecurityDelegation (can be used to authenticate remotely)\n");
		}
		else
		{
			printf("\tUnknown impersonation level\n");
		}
	}
	else
	{
		printf("\tUnknown token type\n");
	}
	//#endif

	#ifdef DEBUG
	printf("\tAuthentication Id: %d\n", token_stats->AuthenticationId);
	#endif

	success = LsaGetLogonSessionData(&token_stats->AuthenticationId, &logon_session_data);
	if(success == STATUS_SUCCESS)
	{
		*session_logon_type = logon_session_data->LogonType;
		/*
		  UndefinedLogonType,
		  Interactive,
		  Network,
		  Batch,
		  Service,
		  Proxy,
		  Unlock,
		  NetworkCleartext,
		  NewCredentials,
		  RemoteInteractive,
		  CachedInteractive,
		  CachedRemoteInteractive,
		  CachedUnlock
		*/
		//#ifdef DEBUG
		if(logon_session_data->LogonType == Network)
		{
			printf("\tLogon type: Network (%d) (creds are not in memory)\n", logon_session_data->LogonType);
		}
		else if(logon_session_data->LogonType == Interactive)
		{
			printf("\tLogon type: Interactive (%d) (creds are supposed to be in memory)\n", logon_session_data->LogonType);
		}
		else if(logon_session_data->LogonType == RemoteInteractive)
		{
			printf("\tLogon type: Remote Interactive (%d) (creds are supposed to be in memory)\n", logon_session_data->LogonType);
		}
		else if(logon_session_data->LogonType == NetworkCleartext)
		{
			printf("\tLogon type: Network Cleartext (%d) (creds are supposed to be in memory)\n", logon_session_data->LogonType);
		}
		else
		{
			printf("\tLogon type: %d (creds are supposed to be in memory)\n", logon_session_data->LogonType);
		}
		//#endif
	}
	else
	{
		#ifdef DEBUG
		printf("\t[-]Unable to get logon session, NTSTATUS = %d\n", success);
		#endif
		*session_logon_type = 0;
	}

	free(token_stats);

	return 0;
}

int Token::getTokenUser(char** username, char** domain)
{
	DWORD n;
	BOOL success;
	TOKEN_USER* token_user;
	SID_NAME_USE sid_name_use;

    if (!GetTokenInformation(this->hToken, TokenUser, 0, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		#ifdef DEBUG
		printf("\tUnable to get token informations: %d\n", GetLastError());
		#endif
		return GetLastError();
	}

	token_user = (TOKEN_USER*)malloc(n);

	if (!GetTokenInformation(this->hToken, TokenUser, (PVOID)token_user, n, &n))
	{
		#ifdef DEBUG
		printf("\tUnable to get token informations: %d\n", GetLastError());
		#endif
		free(token_user);
		return GetLastError();
	}

	DWORD usernamesize = 0;
	DWORD domainsize = 0;
	LookupAccountSid(NULL, token_user->User.Sid, NULL, &usernamesize, NULL, &domainsize, &sid_name_use);

	#ifdef DEBUG
	printf("\tusername size: %d\n", usernamesize);
	printf("\tdomainsize size: %d\n", domainsize);
	#endif
	*username = (char*)malloc(usernamesize);
	*domain = (char*)malloc(domainsize);

	success = LookupAccountSid(NULL, token_user->User.Sid, *username, &usernamesize, *domain, &domainsize, &sid_name_use);
	if(!success)
	{
		#ifdef DEBUG
		printf("\tUnable to lookup account sid\n");
		#endif
		free(token_user);
		return GetLastError();
	}
	else
	{
		#ifdef DEBUG
		printf("\t[+] SID: %s\\%s\n", *domain, *username);
		#endif
	}

	free(token_user);

	return 0;
}

std::list<Privilege>* Token::getTokenPrivs()
{
	DWORD n;
	BOOL success;
	TOKEN_PRIVILEGES* token_privs;

	if (!GetTokenInformation(this->hToken, TokenPrivileges, 0, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		#ifdef DEBUG
		printf("\tUnable to get token informations: %d\n", GetLastError());
		#endif
		return NULL;
	}

	token_privs = (TOKEN_PRIVILEGES*)malloc(n);

	if (!GetTokenInformation(this->hToken, TokenPrivileges, (PVOID)token_privs, n, &n))
	{
		#ifdef DEBUG
		printf("\tUnable to get token informations: %d\n", GetLastError());
		#endif
		free(token_privs);
		return NULL;
	}

	#ifdef DEBUG
	printf("\tThis token has %d privileges\n", token_privs->PrivilegeCount);
	#endif

	std::list<Privilege>* privilege_list = new std::list<Privilege>();

    for (int i = 0; i < token_privs->PrivilegeCount; i++ )
    {
		LUID_AND_ATTRIBUTES lattr = token_privs->Privileges[i];
        
		DWORD strsize = 0;
		LookupPrivilegeNameA(NULL, &lattr.Luid, NULL, &strsize);

		char* privilege_name = (char*)malloc(strsize+1); // priv name + status
		if (privilege_name == NULL)
		{
			#ifdef DEBUG
			printf("malloc failure\n", privilege_name);
			#endif

			delete privilege_list;

			return NULL;
		}

		BOOL success = LookupPrivilegeNameA(NULL, &lattr.Luid, privilege_name, &strsize);
		if(success)
		{
			#ifdef DEBUG
			printf("\t- %s (%d)\n", privilege_name, lattr.Attributes);
			#endif

			bool enabled = (lattr.Attributes& SE_PRIVILEGE_ENABLED) != 0;
			bool enabled_by_default = (lattr.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
			bool removed = (lattr.Attributes & SE_PRIVILEGE_REMOVED) != 0;
			bool used_for_access = (lattr.Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) != 0;

			#ifdef DEBUG
			printf("\t* priv: %s\n", privilege_name);
			#endif

			privilege_list->push_back(Privilege(std::string(privilege_name), enabled, enabled_by_default, removed, used_for_access));

			free(privilege_name);
		}
    }

	free(token_privs);

	return privilege_list;
}

int Token::enablePrivilege(const char* privilege_name)
{
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;

	if(LookupPrivilegeValue(NULL, privilege_name, &luidDebug) != FALSE)
	{
		tokenPriv.PrivilegeCount           = 1;
		tokenPriv.Privileges[0].Luid       = luidDebug;
		tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if(AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, NULL, NULL) != FALSE)
		{
			return 0;
		}
		else
		{
			return GetLastError();
		}
	}

	#ifdef DEBUG
	printf("Unable to lookup privilege name\n");
	#endif

	return -1;
}

int Token::impersonate()
{
	BOOL res = ImpersonateLoggedOnUser(this->hToken);
	if(!res)
	{
		#ifdef DEBUG
		printf("Unable to impersonate: %d\n", GetLastError());
		#endif
		return GetLastError();
	}

	return 0;
}

int Token::createProcess(const wchar_t* application)
{
	STARTUPINFOW si = {};
	PROCESS_INFORMATION pi = {};
	BOOL res = CreateProcessWithTokenW(this->hToken, LOGON_WITH_PROFILE, application, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (res == 0)
		return GetLastError();
	else
		return 0;
}

Token* createToken(const char* domain, const char* username, const char* password)
{
	HANDLE hToken = NULL;
	BOOL res = LogonUser(username, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken);
	if(!res)
	{
		#ifdef DEBUG
		printf("Unable to create token: %d\n", GetLastError());
		#endif
		return NULL;
	}

	Token* token = new Token(hToken);

	return token;
}

int Token::loadUserProfile()
{
	#ifdef DEBUG
	printf("Token: %d\n", this->hToken);
	#endif

	PROFILEINFO profile_info;
	memset(&profile_info, 0, sizeof(PROFILEINFO));
	profile_info.dwSize = sizeof(PROFILEINFO);

	char* username;
	char* domain;

	this->getTokenUser(&username, &domain);
	char* dom_user = (char*)malloc(strlen(username)+strlen(domain)+2);
	sprintf_s(dom_user, strlen(username) + strlen(domain) + 2, "%s\\%s", domain, username);
	profile_info.lpUserName = dom_user;

	BOOL b = LoadUserProfile(this->hToken, &profile_info);

	#ifdef DEBUG
	printf("LoadUserProfile: %d: %d\n", b, GetLastError());
	#endif

	free(username);
	free(domain);
	free(dom_user);

	return b;
}

Token* Token::duplicate()
{
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken = new HANDLE;

	if (!DuplicateTokenEx(this->hToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken))
	{
		return NULL;
	}

	return new Token(pNewToken);
}

Privilege::Privilege(std::string name, bool enabled, bool enabled_by_default, bool removed, bool used_for_access)
{
	this->name = name;
	this->enabled = enabled;
	this->enabled_by_default = enabled_by_default;
	this->removed = removed;
	this->used_for_access = used_for_access;
}