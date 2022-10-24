/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "security.h"

SecurityDescriptor::SecurityDescriptor(PSECURITY_DESCRIPTOR security_descriptor)
{
	this->security_descriptor = security_descriptor;
}

int SecurityDescriptor::init()
{
	BOOL dacl_defaulted;
	if(!GetSecurityDescriptorDacl(this->security_descriptor, &this->dacl_present, &this->pacl, &dacl_defaulted))
	{
		#ifdef DEBUG
		printf("[SecurityDescriptor] GetSecurityDescriptorDacl: %d\n", GetLastError());
		#endif
		return GetLastError();
	}

	return 0;
}

SecurityDescriptor::~SecurityDescriptor() {}

BOOL SecurityDescriptor::access_to_all()
{
	if(this->dacl_present == TRUE && this->pacl == NULL)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL SecurityDescriptor::access_to_none()
{
	return !this->dacl_present;
}

int SecurityDescriptor::get_owner(char** username, char** domain)
{
	// Parse owner
	PSID owner;
	BOOL owner_defaulted;
	if(!GetSecurityDescriptorOwner(security_descriptor, &owner, &owner_defaulted))
	{
		#ifdef DEBUG
		printf("[SecurityDescriptor] GetSecurityDescriptorOwner failed: %d\n", GetLastError());
		#endif
		return GetLastError();
	}

	int res = lookup_sid(owner, domain, username);
	if(res != 0)
	{
		#ifdef DEBUG
		printf("[SecurityDescriptor] Unable to lookup owner account sid: %d\n", res);
		#endif
		return res;
	}

	#ifdef DEBUG
	printf("[SecurityDescriptor] Owner: %s\\%s\n", *domain, *username);
	#endif

	return 0;
}

int SecurityDescriptor::get_ace_list(std::list<ACE>* ace_list)
{
	if(this->dacl_present == FALSE || this->pacl == NULL)
	{
		return -1;
	}

	ACL_SIZE_INFORMATION aclsizeinfo;
	//We need to parse the acl
	if (GetAclInformation(this->pacl, &aclsizeinfo, sizeof(aclsizeinfo), AclSizeInformation) == FALSE)  
	{  
		#ifdef DEBUG
		printf("[SecurityDescriptor] GetAclInformation failed. GetLastError returned: %d\n",  GetLastError());
		#endif
		return GetLastError();  
	}

	HRESULT hr = MQ_OK;
	ACCESS_ALLOWED_ACE * pAce = NULL;
	// Loop through the ACEs and display the information.  
	for (DWORD cAce = 0; cAce < aclsizeinfo.AceCount && hr == MQ_OK; cAce++)  
	{
		// Get ACE info  
		if (GetAce(this->pacl, cAce, (LPVOID*)&pAce) == FALSE)  
		{
			#ifdef DEBUG
			printf("[SecurityDescriptor] GetAce failed. GetLastError returned: %d\n",  GetLastError());
			#endif
			continue;
		}

		ACE ace;

		int res = lookup_sid(&pAce->SidStart, &ace.domain, &ace.username);
		if(res != 0)
		{
			#ifdef DEBUG
			printf("[SecurityDescriptor] Unable to lookup owner account sid: %d\n", res);
			#endif
			return res;
		}

		ace.ace_type = pAce->Header.AceType;
		ace.access = pAce->Mask;

		ace_list->push_back(ace);
	}

	return 0;
}

int lookup_sid(PSID pSid, char** domain, char** username)
{
	#ifdef DEBUG
	printf("[LookupSID] >>> %d\n", pSid);
	#endif

	BOOL success;
	SID_NAME_USE sid_name_use;
	DWORD usernamesize = 0;
	DWORD domainsize = 0;
	success = LookupAccountSid(NULL, pSid, NULL, &usernamesize, NULL, &domainsize, &sid_name_use);
	if(!success)
	{
		#ifdef DEBUG
		printf("[LookupSID] >> %d\n", GetLastError());
		#endif
	}
	#ifdef DEBUG
	printf("[LookupSID] > %d\n", domainsize);
	printf("[LookupSID] > %d\n", usernamesize);
	#endif

	domainsize = domainsize*2;
	usernamesize = usernamesize*2;

	*username = (char*)malloc(usernamesize);
	*domain = (char*)malloc(domainsize);
	success = LookupAccountSid(NULL, pSid, *username, &usernamesize, *domain, &domainsize, &sid_name_use);
	if(!success)
	{
		return GetLastError();
	}

	return 0;
}

int parse_security_descriptor(PSECURITY_DESCRIPTOR security_descriptor)
{
	if (security_descriptor == NULL)
	{
		#ifdef DEBUG
		printf("No security descriptor\n");
		#endif
		return -1;
	}

	// Parse owner
	BOOL success;
	char* owner_username;
	char* owner_domain;
	PSID owner;
	BOOL owner_defaulted;
	if(!GetSecurityDescriptorOwner(security_descriptor, &owner, &owner_defaulted))
	{
		#ifdef DEBUG
		printf("[SecurityDescriptor] GetSecurityDescriptorOwner failed: %d\n", GetLastError());
		#endif
		return GetLastError();
	}

	int res = lookup_sid(owner, &owner_domain, &owner_username);
	if(res != 0)
	{
		#ifdef DEBUG
		printf("[SecurityDescriptor] Unable to lookup owner account sid: %d\n", res);
		#endif
		return res;
	}

	#ifdef DEBUG
	printf("[SecurityDescriptor] Owner: %s\\%s\n", owner_domain, owner_username);
	#endif

	#ifdef DEBUG
	printf("[SecurityDescriptor] Parsing DACL\n");
	#endif

	// DACL
	PACL pacl = NULL;  
	BOOL dacl_present = FALSE;
	BOOL dacl_defaulted = TRUE;

	success = GetSecurityDescriptorDacl(security_descriptor, &dacl_present, &pacl, &dacl_defaulted);
	if(!success)
	{
		#ifdef DEBUG
		printf("[SecurityDescriptor] Unable to lookup dacl: %d\n", GetLastError());
		#endif
		return GetLastError();
	}

	#ifdef DEBUG
	printf("[SecurityDescriptor] done\n");
	#endif

	if(dacl_present == FALSE)
	{
		// No dacl, no one has access to this object
		#ifdef DEBUG
		printf("[SecurityDescriptor] No dacl, no one has access to this object\n");
		#endif
	}
	else if(pacl == NULL)
	{
		// NULL acl, everyone has access to this object
		#ifdef DEBUG
		printf("[SecurityDescriptor] NULL acl, everyone has access to this object\n");
		#endif
	}
	else
	{
		ACL_SIZE_INFORMATION aclsizeinfo;
		//We need to parse the acl
		if (GetAclInformation(pacl, &aclsizeinfo, sizeof(aclsizeinfo), AclSizeInformation) == FALSE)  
		{  
			#ifdef DEBUG
			printf("[SecurityDescriptor] GetAclInformation failed. GetLastError returned: %d\n",  GetLastError());
			#endif
			return GetLastError();  
		}

		 HRESULT hr = MQ_OK;
		 ACCESS_ALLOWED_ACE * pAce = NULL;
		// Loop through the ACEs and display the information.  
		for (DWORD cAce = 0; cAce < aclsizeinfo.AceCount && hr == MQ_OK; cAce++)  
		{
			// Get ACE info  
			if (GetAce(pacl, cAce, (LPVOID*)&pAce) == FALSE)  
			{
				#ifdef DEBUG
				printf("[SecurityDescriptor] GetAce failed. GetLastError returned: %d\n",  GetLastError());
				#endif
				continue;
			}

			char* ace_username = NULL;
			char* ace_domain = NULL;

			int res = lookup_sid(&pAce->SidStart, &ace_domain, &ace_username);
			if(res != 0)
			{
				#ifdef DEBUG
				printf("[SecurityDescriptor] Unable to lookup owner account sid: %d\n", res);
				#endif
				return res;
			}

			switch(pAce->Header.AceType)  
			{  
				case ACCESS_ALLOWED_ACE_TYPE:
					#ifdef DEBUG
					printf("[SecurityDescriptor] Permissions granted to %s\\%s\n", ace_domain, ace_username);
					#endif  
					DisplayPermissions(pAce->Mask);  
					break;  
  
				case ACCESS_DENIED_ACE_TYPE:  
					#ifdef DEBUG
					printf("[SecurityDescriptor] Permissions denied to %s\\%s\n", ace_domain, ace_username);
					#endif  
					DisplayPermissions(pAce->Mask);  
					break;  
  
				default:  
					#ifdef DEBUG
					printf("[SecurityDescriptor] Unknown ACE\n");
					#endif
					break;
		    }  

			free(ace_domain);
		    free(ace_username);
		}
	}
	
	free(owner_username);
	free(owner_domain);

	return 0;
}

HRESULT DisplayPermissions(ACCESS_MASK amMask)  
{  
  
  if ((amMask & MQSEC_QUEUE_GENERIC_ALL) == MQSEC_QUEUE_GENERIC_ALL)  
  {  
    wprintf(L"\tFull Control\n");  
  }  
  
  if ((amMask & MQSEC_DELETE_QUEUE) == MQSEC_DELETE_QUEUE)  
  {  
    wprintf(L"\tDelete\n");  
  }  
  
  if ((amMask & MQSEC_RECEIVE_MESSAGE) == MQSEC_RECEIVE_MESSAGE)  
  {  
    wprintf(L"\tReceive Message\n");  
  }  
  
  if ((amMask & MQSEC_DELETE_MESSAGE) == MQSEC_DELETE_MESSAGE)  
  {  
    wprintf(L"\tDelete Message\n");  
  }  
  
  if ((amMask & MQSEC_PEEK_MESSAGE) == MQSEC_PEEK_MESSAGE)  
  {  
    wprintf(L"\tPeek Message\n");  
  }  
  
  if ((amMask & MQSEC_RECEIVE_JOURNAL_MESSAGE) == MQSEC_RECEIVE_JOURNAL_MESSAGE)  
  {  
    wprintf(L"\tReceive Journal Message\n");  
  }  
  
  if ((amMask & MQSEC_DELETE_JOURNAL_MESSAGE) == MQSEC_DELETE_JOURNAL_MESSAGE)  
  {  
    wprintf(L"\tDelete Journal Message\n");  
  }  
  
  if ((amMask & MQSEC_GET_QUEUE_PROPERTIES) == MQSEC_GET_QUEUE_PROPERTIES)  
  {  
    wprintf(L"\tGet Properties\n");  
  }  
  
  if ((amMask & MQSEC_SET_QUEUE_PROPERTIES) == MQSEC_SET_QUEUE_PROPERTIES)  
  {  
    wprintf(L"\tSet Properties\n");  
  }  
  
  if ((amMask & MQSEC_GET_QUEUE_PERMISSIONS) == MQSEC_GET_QUEUE_PERMISSIONS)  
  {  
    wprintf(L"\tGet Permissions\n");  
  }  
  
  if ((amMask & MQSEC_CHANGE_QUEUE_PERMISSIONS) == MQSEC_CHANGE_QUEUE_PERMISSIONS)  
  {  
    wprintf(L"\tSet Permissions\n");  
  }  
  
  if ((amMask & MQSEC_TAKE_QUEUE_OWNERSHIP) == MQSEC_TAKE_QUEUE_OWNERSHIP)  
  {  
    wprintf(L"\tTake Ownership\n");  
  }  
  
  if ((amMask & MQSEC_WRITE_MESSAGE) == MQSEC_WRITE_MESSAGE)  
  {  
    wprintf(L"\tSend Message\n");  
  }  
  
  return S_OK;  
} 


void init_random()
{
	srand(time(NULL));
}

void gen_random(char* s, const int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; i++)
	{
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}