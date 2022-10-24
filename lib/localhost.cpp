/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "localhost.h"

Localhost::Localhost() {}

Localhost::~Localhost() {}

std::list<std::string>* Localhost::listSubKeys(const char* reg_path)
{
	std::list<std::string>* keys;

	TCHAR achKey[MAX_KEY_LENGTH] = TEXT("");
	DWORD cbName;
	TCHAR achClass[MAX_PATH] = TEXT("");
	DWORD cchClassName = MAX_PATH;
	DWORD cSubKeys=0;
	DWORD cbMaxSubKey;
	DWORD cchMaxClass;
	DWORD cValues;
	DWORD cchMaxValue;
	DWORD cbMaxValueData;
	DWORD cbSecurityDescriptor;
	FILETIME ftLastWriteTime;

	DWORD i, retCode;
	TCHAR achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	HKEY hKey = NULL;
	LONG lResult = RegOpenKey(
		HKEY_LOCAL_MACHINE,
		reg_path,
		&hKey);
	if(lResult != ERROR_SUCCESS)
	{
		return NULL;
	}

	keys = new std::list<std::string>();

	retCode = RegQueryInfoKey(hKey, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues, &cchMaxValue, &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime);
	if(cSubKeys)
	{
		if (cSubKeys)
		{
			for (i=0; i<cSubKeys; i++) 
			{ 
				cbName = MAX_KEY_LENGTH;
				retCode = RegEnumKeyEx(hKey, i,
						 achKey, 
						 &cbName, 
						 NULL, 
						 NULL, 
						 NULL, 
						 &ftLastWriteTime); 
				if (retCode == ERROR_SUCCESS) 
				{
					keys->push_back(std::string(reg_path) + std::string("\\") + std::string(achKey));
				}
			}
		} 
	}

	RegCloseKey(hKey);

	return keys;
}

std::string Localhost::getStringRegKey(HKEY hKey, const char* valueName)
{
	char szBuffer[512];
    DWORD dwBufferSize = sizeof(szBuffer);
    ULONG nError;
    nError = RegQueryValueEx(hKey, valueName, 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
    if (ERROR_SUCCESS == nError)
    {
		return std::string(szBuffer);
    }
    return std::string("");
}

vectByte Localhost::screenshot()
{
	// Source: https://stackoverflow.com/a/28248531

    // Screen width and height
	int x_start = GetSystemMetrics(SM_XVIRTUALSCREEN);
	int y_start = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int width   = GetSystemMetrics(SM_CXVIRTUALSCREEN) - GetSystemMetrics(SM_XVIRTUALSCREEN);
    int height   = GetSystemMetrics(SM_CYVIRTUALSCREEN) - GetSystemMetrics(SM_YVIRTUALSCREEN);

    // copy screen to bitmap
    HDC     hScreen = GetDC(NULL);
    HDC     hDC     = CreateCompatibleDC(hScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
    HGDIOBJ old_obj = SelectObject(hDC, hBitmap);
    BOOL    bRet    = BitBlt(hDC, 0, 0, width, height, hScreen, x_start, y_start, SRCCOPY);

	// Save bitmap to mem as png
	CImage image;
	image.Attach(hBitmap);
	vectByte png_buffer;
	image_to_buffer_png(image, png_buffer);

	 // clean up
    SelectObject(hDC, old_obj);
    DeleteDC(hDC);
    ReleaseDC(NULL, hScreen);
    DeleteObject(hBitmap);

	return png_buffer;
}

void image_to_buffer_png(const CImage &image,  vectByte &png_buffer)
{
	IStream *stream = NULL;

	HRESULT  hr = CreateStreamOnHGlobal(0, TRUE, &stream);
	if (!SUCCEEDED(hr))
		return;

	image.Save(stream, Gdiplus::ImageFormatPNG);

	ULARGE_INTEGER liSize;
	IStream_Size(stream, &liSize);

	DWORD len = liSize.LowPart;
	IStream_Reset(stream);
	png_buffer.resize(len);
	IStream_Read(stream, &png_buffer[0], len);

	stream->Release();

	return;
}



SystemInfo* Localhost::getSystemInfo()
{
	/*
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);

	OSVERSIONINFOEX osinfo;
	osinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
#pragma warning(suppress : 4996)
	GetVersionEx((LPOSVERSIONINFO)&osinfo);

	return SystemInfo(siSysInfo.wProcessorArchitecture, siSysInfo.dwNumberOfProcessors, osinfo.dwMajorVersion, osinfo.dwMinorVersion, osinfo.dwBuildNumber, osinfo.wProductType);
	*/

	SystemInfo* system_info = NULL;

	IWbemLocator* wbemLocator{ nullptr };
	IWbemServices* wbemServices{ nullptr };

	if (!initializeCom())
		return NULL;

	if (!setUpWBEM(wbemLocator, wbemServices))
		return NULL;

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	BSTR bstr_wql = SysAllocString(L"WQL");
	BSTR bstr_sql = SysAllocString(L"SELECT * FROM Win32_OperatingSystem");

	// For example, get the name of the operating system
	IEnumWbemClassObject* pEnumerator{ nullptr };
	HRESULT hres = wbemServices->ExecQuery(
		bstr_wql,
		bstr_sql,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator);

	if (FAILED(hres))
	{
		wbemServices->Release();
		wbemLocator->Release();
		CoUninitialize();
		return NULL;               // Program has failed.
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject* pclsObj{ nullptr };
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;
		// Get the value of the Name property
		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);

		if (FAILED(hr))
			std::cout << "Failed to get name " << std::endl;

		std::wstring name = std::wstring(vtProp.bstrVal);
		std::wstring os_version = name.substr(0, name.find('|'));

		VariantClear(&vtProp);

		// Get the value of the BuildNumber property
		hr = pclsObj->Get(L"BuildNumber", 0, &vtProp, 0, 0);

		if (FAILED(hr))
			std::cout << "Failed to get version " << std::endl;

		std::wstring build = std::wstring(vtProp.bstrVal);

		VariantClear(&vtProp);

		// Get the value of the InstallDate property
		hr = pclsObj->Get(L"InstallDate", 0, &vtProp, 0, 0);

		if (FAILED(hr))
			std::cout << "Failed to get version " << std::endl;

		std::wstring date_str = std::wstring(vtProp.bstrVal);
		std::wstring install_date = date_str.substr(0, 4) + L"-" + date_str.substr(4, 2) + L"-" + date_str.substr(6, 2) + L" " + date_str.substr(8, 2) + L":" + date_str.substr(10, 2);

		VariantClear(&vtProp);

		// Get the value of the LastBootUpTime property
		hr = pclsObj->Get(L"LastBootUpTime", 0, &vtProp, 0, 0);

		if (FAILED(hr))
			std::cout << "Failed to get version " << std::endl;

		date_str = std::wstring(vtProp.bstrVal);
		std::wstring lastboot_date = date_str.substr(0, 4) + L"-" + date_str.substr(4, 2) + L"-" + date_str.substr(6, 2) + L" " + date_str.substr(8, 2) + L":" + date_str.substr(10, 2);

		VariantClear(&vtProp);

		// Get the value of the OSArchitecture property
		hr = pclsObj->Get(L"OSArchitecture", 0, &vtProp, 0, 0);

		if (FAILED(hr))
			std::cout << "Failed to get version " << std::endl;

		std::wstring os_arch = std::wstring(vtProp.bstrVal);

		VariantClear(&vtProp);

		pclsObj->Release();

		system_info = new SystemInfo(os_version + L" Build " + build, os_arch, install_date, lastboot_date);
	}

	// Cleanup
	// ========

	wbemServices->Release();
	wbemLocator->Release();
	pEnumerator->Release();
	CoUninitialize();

	return system_info;
}


std::list<Application> Localhost::getApplications()
{
	std::list<Application> apps_list;
	std::list<std::string>::const_iterator it;

	const char* registry_path = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

	std::list<std::string>* reg_keys = this->listSubKeys(registry_path);

	if (reg_keys != NULL)
	{
		for (it = reg_keys->begin(); it != reg_keys->end(); it++)
		{
			HKEY hKey = NULL;
			LONG lResult = RegOpenKey(HKEY_LOCAL_MACHINE, (*it).c_str(), &hKey);
			if (lResult == ERROR_SUCCESS)
			{
				std::string app_name = this->getStringRegKey(hKey, "DisplayName");

				if (strlen(app_name.c_str()) != 0)
				{
					std::string app_version = this->getStringRegKey(hKey, "DisplayVersion");

					apps_list.push_back(Application(app_name, app_version));
				}
			}
		}
	}

	registry_path = "Software\\Microsoft\\Windows\\CurrentVersion‌​\\Uninstall";

	reg_keys = this->listSubKeys(registry_path);

	if (reg_keys != NULL)
	{
		for (it = reg_keys->begin(); it != reg_keys->end(); it++)
		{
			HKEY hKey = NULL;
			LONG lResult = RegOpenKey(HKEY_LOCAL_MACHINE, (*it).c_str(), &hKey);
			if (lResult == ERROR_SUCCESS)
			{
				std::string app_name = this->getStringRegKey(hKey, "DisplayName");

				if (strlen(app_name.c_str()) != 0)
				{
					std::string app_version = this->getStringRegKey(hKey, "DisplayVersion");

					apps_list.push_back(Application(app_name, app_version));
				}
			}
		}
	}

	return apps_list;
}

std::list<RDPServer> Localhost::getRDPServers()
{
	std::list<RDPServer> rdp_list;

	const char* registry_path = "Software\\Microsoft\\Terminal Server Client\\Servers";

	std::list<std::string>* reg_keys = this->listSubKeys(registry_path);

	if (reg_keys != NULL)
	{
		std::list<std::string>::const_iterator it;
		for (it = reg_keys->begin(); it != reg_keys->end(); it++)
		{
			HKEY hKey = NULL;
			LONG lResult = RegOpenKey(HKEY_LOCAL_MACHINE, (*it).c_str(), &hKey);
			if (lResult == ERROR_SUCCESS)
			{
				std::string username = this->getStringRegKey(hKey, "UsernameHint");

				char* pos = strstr((char*)(*it).c_str(), "\\");

				std::string hostname = std::string(pos + 1);

				if (strlen(username.c_str()) != 0)
				{
					rdp_list.push_back(RDPServer(username, hostname));
				}
			}
		}
	}

	return rdp_list;
}

SystemInfo::SystemInfo(std::wstring os_name, std::wstring os_arch, std::wstring install_date, std::wstring last_boot_date)
{
	this->os_name = os_name;
	this->os_arch = os_arch;
	this->install_date = install_date;
	this->last_boot_date = last_boot_date;
}

Application::Application(char* name, char* version)
{
	this->name = std::string(name);
	this->version = std::string(version);
}

Application::Application(std::string name, std::string version)
{
	this->name = name;
	this->version = version;
}

RDPServer::RDPServer(std::string username, std::string server)
{
	this->username = username;
	this->server = server;
}

bool initializeCom() {
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

bool setUpWBEM(IWbemLocator*& wbemLocator, IWbemServices*& wbemServices) {
	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------
	HRESULT hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&wbemLocator);

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

	hres = wbemLocator->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		nullptr,                    // User name. NULL = current user
		nullptr,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		0,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&wbemServices            // pointer to IWbemServices proxy
	);

	if (FAILED(hres))
	{
		std::cout << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
		wbemLocator->Release();
		CoUninitialize();
		return false;                // Program has failed.
	}

	//std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;


	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = CoSetProxyBlanket(
		wbemServices,                // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		nullptr,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		nullptr,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);

	if (FAILED(hres))
	{
		std::cout << "Could not set proxy blanket. Error code = 0x"
			<< std::hex << hres << std::endl;
		wbemServices->Release();
		wbemLocator->Release();
		CoUninitialize();
		return false;               // Program has failed.
	}

	return true;
}