/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "com.h"

COM::COM()
{
	this->initializeCom();
}

COM::~COM()
{
	CoUninitialize();
}

bool COM::initializeCom() {
	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		std::cout << "Failed to initialize COM library. Error code = 0x"
			<< std::hex << hres << std::endl;
		return false;                  // Program has failed.
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		nullptr,
		-1,                          // COM authentication
		nullptr,                        // Authentication services
		nullptr,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		nullptr,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		nullptr                         // Reserved
	);

	if (FAILED(hres))
	{
		std::cout << "Failed to initialize security. Error code = 0x"
			<< std::hex << hres << std::endl;
		CoUninitialize();
		return false;                    // Program has failed.
	}
	return true;
}

bool COM::CreateInstance(IID rclsid, IID riid, LPVOID* ppv, const wchar_t* host, const wchar_t* domain, const wchar_t* username, const wchar_t* password)
{
	// Step 3: ---------------------------------------------------
	// Obtain the instance -------------------------
	MULTI_QI mqi[1] = { &riid, NULL, 0 };

	DWORD clsctx;
	COSERVERINFO* pCoServerInfo;
	COAUTHIDENTITY* pCoAuthIdentity;
	COAUTHINFO* coAuthInfo;
	if (host == NULL)
	{
		clsctx = CLSCTX_INPROC_SERVER;
		pCoServerInfo = NULL;
		pCoAuthIdentity = NULL;
		coAuthInfo = NULL;
	}
	else
	{
		clsctx = CLSCTX_REMOTE_SERVER;

		if (username != NULL)
		{
			pCoAuthIdentity = (COAUTHIDENTITY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(COAUTHIDENTITY));
			pCoAuthIdentity->User = (USHORT*)username;
			pCoAuthIdentity->UserLength = wcslen(username);
			if (password != NULL)
			{
				pCoAuthIdentity->Password = (USHORT*)password;
				pCoAuthIdentity->PasswordLength = wcslen(password);
			}
			else
			{
				pCoAuthIdentity->Password = (USHORT*)L"";
				pCoAuthIdentity->PasswordLength = 0;
			}
			if (domain != NULL)
			{
				pCoAuthIdentity->Domain = (USHORT*)domain;
				pCoAuthIdentity->DomainLength = wcslen(domain);
			}
			else
			{
				pCoAuthIdentity->Domain = (USHORT*)L"";
				pCoAuthIdentity->DomainLength = 0;
			}
			pCoAuthIdentity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
		}
		else
		{
			pCoAuthIdentity = NULL;
		}

		coAuthInfo = (COAUTHINFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(COAUTHINFO));
		coAuthInfo->dwAuthnSvc = RPC_C_AUTHN_WINNT;
		coAuthInfo->dwAuthzSvc = RPC_C_AUTHZ_NONE;
		coAuthInfo->pwszServerPrincName = NULL;
		coAuthInfo->dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
		coAuthInfo->dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
		coAuthInfo->pAuthIdentityData = pCoAuthIdentity;
		coAuthInfo->dwCapabilities = EOAC_NONE;

		pCoServerInfo = (COSERVERINFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(COSERVERINFO));;
		pCoServerInfo->dwReserved1 = 0;
		pCoServerInfo->dwReserved2 = 0;
		pCoServerInfo->pwszName = (LPWSTR)host;
		pCoServerInfo->pAuthInfo = coAuthInfo;
	}

	HRESULT hres = CoCreateInstanceEx(
		rclsid,
		NULL,
		clsctx,
		pCoServerInfo,
		1,
		mqi
	);

	if (pCoAuthIdentity != NULL)
		HeapFree(GetProcessHeap(), 0, pCoAuthIdentity);
	if (coAuthInfo != NULL)
		HeapFree(GetProcessHeap(), 0, coAuthInfo);
	if (pCoServerInfo != NULL)
		HeapFree(GetProcessHeap(), 0, pCoServerInfo);

	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Error during the CoCreateInstance: %x\n", hres);
#endif
		CoUninitialize();
		return false;                 // Program has failed.
	}

	if (mqi->hr == S_OK)
		(*ppv) = (LPVOID*)mqi->pItf;
	else
		(*ppv) = NULL;

	return true;
}

