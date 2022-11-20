/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "wmi.h"

WMI::WMI()
{
	this->initializeCom();
}

WMI::~WMI()
{
	CoUninitialize();
}

bool WMI::execute(const char* host, const char* username, const char* password, const char* command)
{
	IWbemLocator* wbemLocator = NULL;
	IWbemServices* wbemServices = NULL;

	bool success = this->setUpWBEM(host, username, password, &wbemLocator, &wbemServices);
	if (!success)
		return false;

	// Step 7: --------------------------------------------------
// Use the IWbemServices pointer to make requests of WMI ----

// set up to call the Win32_Process::Create method
	BSTR MethodName = SysAllocString(L"Create");
	BSTR ClassName = SysAllocString(L"Win32_Process");

	IWbemClassObject* pClass = NULL;
	HRESULT hres = wbemServices->GetObject(ClassName, 0, NULL, &pClass, NULL);
	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Failed to get object Win32_Process: %d\n", hres);
#endif

		SysFreeString(ClassName);
		SysFreeString(MethodName);
		wbemServices->Release();
		wbemLocator->Release();

		return false;               // Program has failed.
	}

	IWbemClassObject* pInParamsDefinition = NULL;
	hres = pClass->GetMethod(MethodName, 0,
		&pInParamsDefinition, NULL);
	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Failed to get object Create: %d\n", hres);
#endif

		SysFreeString(ClassName);
		SysFreeString(MethodName);
		wbemServices->Release();
		wbemLocator->Release();
		
		return false;               // Program has failed.
	}

	IWbemClassObject* pClassInstance = NULL;
	hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

	// Exec part
	wchar_t* cmd = (wchar_t*)malloc(sizeof(wchar_t) * (strlen(command) + 1));
	MultiByteToWideChar(CP_ACP, 0, command, -1, cmd, sizeof(wchar_t) * (strlen(command)));

	// Create the values for the in parameters
	VARIANT varCommand;
	varCommand.vt = VT_BSTR;
	varCommand.bstrVal = _bstr_t(cmd);

	// Store the value for the in parameters
	hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

	// Execute Method
	IWbemClassObject* pOutParams = NULL;
	hres = wbemServices->ExecMethod(ClassName, MethodName, 0, NULL, pClassInstance, &pOutParams, NULL);

	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Could not execute method: %d\n", GetLastError());
#endif

		VariantClear(&varCommand);
		SysFreeString(ClassName);
		SysFreeString(MethodName);
		pClass->Release();
		pClassInstance->Release();
		pInParamsDefinition->Release();
		pOutParams->Release();
		wbemServices->Release();
		wbemLocator->Release();

		return false;               // Program has failed.
	}

	// Clean up
	//--------------------------
	VariantClear(&varCommand);
	//VariantClear(&varReturnValue);
	SysFreeString(ClassName);
	SysFreeString(MethodName);
	pClass->Release();
	pClassInstance->Release();
	pInParamsDefinition->Release();
	pOutParams->Release();

#ifdef DEBUG
	printf("Successfully executed command through WMI\n");
#endif

	// Cleanup
	// ========

	wbemServices->Release();
	wbemLocator->Release();

	return true;
}

bool WMI::initializeCom() {
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

bool WMI::setUpWBEM(const char* host, const char* username, const char* password, IWbemLocator** wbemLocator, IWbemServices** wbemServices) {
	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------
	HRESULT hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)wbemLocator);

	if (FAILED(hres))
	{
		std::cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< std::hex << hres << std::endl;
		CoUninitialize();
		return false;                 // Program has failed.
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer wbemServices
	// to make IWbemServices calls.

	wchar_t w_username[MAX_PATH];
	wchar_t w_password[MAX_PATH];
	wchar_t w_host[MAX_PATH];
	wchar_t w_namespace[MAX_PATH];

	if (host == NULL)
	{
		hres = (*wbemLocator)->ConnectServer(
			_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
			nullptr,                    // User name. NULL = current user
			nullptr,                    // User password. NULL = current
			0,                       // Locale. NULL indicates current
			0,                    // Security flags.
			0,                       // Authority (for example, Kerberos)
			0,                       // Context object 
			wbemServices            // pointer to IWbemServices proxy
		);
	}
	else
	{
		MultiByteToWideChar(CP_ACP, 0, host, -1, w_host, MAX_PATH);
		swprintf_s(w_namespace, MAX_PATH, L"\\\\%s\\root\\CIMV2", w_host);

		if (username != NULL)
		{
			MultiByteToWideChar(CP_ACP, 0, username, -1, w_username, MAX_PATH);
			MultiByteToWideChar(CP_ACP, 0, password, -1, w_password, MAX_PATH);

			wprintf(L"Path: %s\n", w_namespace);
			wprintf(L"User: %s\n", w_username);
			wprintf(L"Pass: %s\n", w_password);

			// Connect to the local root\cimv2 namespace
			// and obtain pointer pSvc to make IWbemServices calls.
			hres = (*wbemLocator)->ConnectServer(
				_bstr_t(w_namespace),
				_bstr_t(w_username),
				_bstr_t(w_password),
				0,
				NULL,
				0,
				0,
				wbemServices
			);

			printf("HRES: %x\n", hres);
		}
		else
		{
			// Connect to the local root\cimv2 namespace
			// and obtain pointer pSvc to make IWbemServices calls.
			hres = (*wbemLocator)->ConnectServer(
				_bstr_t(w_namespace),
				NULL,
				NULL,
				0,
				NULL,
				0,
				0,
				wbemServices
			);
		}
	}

	if (FAILED(hres))
	{
		std::cout << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
		(*wbemLocator)->Release();
		CoUninitialize();
		return false;                // Program has failed.
	}

	//std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;

	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	if (host == NULL)
	{
		hres = CoSetProxyBlanket(
			*wbemServices,                // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
			nullptr,                        // Server principal name 
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			nullptr,                        // client identity
			EOAC_NONE                    // proxy capabilities 
		);
	}
	else
	{
		COAUTHIDENTITY* userAcct = NULL;

		if (username != NULL)
		{
			userAcct = (COAUTHIDENTITY*)malloc(sizeof(COAUTHIDENTITY));
			memset(userAcct, 0, sizeof(COAUTHIDENTITY));
			userAcct->PasswordLength = wcslen(w_password);
			userAcct->Password = (USHORT*)w_password;

			wchar_t w_domain[200];
			wchar_t w_usr[200];
			wchar_t* slash = wcschr(w_username, L'\\');
			if (slash == NULL)
			{
				wcscpy_s(w_usr, 200, w_username);
				wcscpy_s(w_domain, 200, L"WORKGROUP");
			}
			else
			{
				wcscpy_s(w_usr, 200, slash + 1);
				wcsncpy_s(w_domain, 200, w_username, slash - w_username);
			}

			userAcct->User = (USHORT*)w_usr;
			userAcct->UserLength = wcslen(w_usr);

			userAcct->Domain = (USHORT*)w_domain;
			userAcct->DomainLength = wcslen(w_domain);
			userAcct->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		}

		hres = CoSetProxyBlanket(
			*wbemServices,                           // Indicates the proxy to set
			RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
			COLE_DEFAULT_PRINCIPAL,         // Server principal name 
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
			userAcct,                       // client identity
			EOAC_NONE                       // proxy capabilities 
		);
	}

	if (FAILED(hres))
	{
		std::cout << "Could not set proxy blanket. Error code = 0x"
			<< std::hex << hres << std::endl;
		(*wbemServices)->Release();
		(*wbemLocator)->Release();
		CoUninitialize();
		return false;               // Program has failed.
	}

	return true;
}