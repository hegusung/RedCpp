/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef SECURITY_HEADER
#define SECURITY_HEADER

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <list>
#include <mq.h>

#include <ctime>

#pragma comment(lib, "Advapi32.lib")

typedef struct ACE {
	char* username;
	char* domain;
	BYTE ace_type;
	DWORD access;
} ACE;

class SecurityDescriptor
{
public:
	SecurityDescriptor(PSECURITY_DESCRIPTOR security_descriptor);
	~SecurityDescriptor();
	int init();
	BOOL access_to_all();
	BOOL access_to_none();
	int get_owner(char** username, char** domain);
	int get_ace_list(std::list<ACE>* ace_list);
private:
	PSECURITY_DESCRIPTOR security_descriptor;
	BOOL dacl_present;
	PACL pacl;
};

int lookup_sid(PSID pSid, char** domain, char** username);

int parse_security_descriptor(PSECURITY_DESCRIPTOR security_descriptor);
HRESULT DisplayPermissions(ACCESS_MASK amMask);

#endif