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

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	UINT  num = 0;          // number of image encoders
	UINT  size = 0;         // size of the image encoder array in bytes

	Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;

	Gdiplus::GetImageEncodersSize(&num, &size);
	if (size == 0)
		return -1;  // Failure

	pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
	if (pImageCodecInfo == NULL)
		return -2;  // Failure

	GetImageEncoders(num, size, pImageCodecInfo);

	for (UINT j = 0; j < num; ++j)
	{
		if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;  // Success
		}
	}

	free(pImageCodecInfo);
	return -3;  // Failure
}

char* Localhost::screenshot(int* size)
{
	// Source: https://stackoverflow.com/a/28248531
	CoInitialize(NULL);

	*size = 0;
	char* data = NULL;
	Gdiplus::Bitmap* bmp = NULL;

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

	// Initialize GDI+.
	Gdiplus::GdiplusStartupInput gdipStartupInput;
	ULONG_PTR gdipToken;
	Gdiplus::GdiplusStartup(&gdipToken, &gdipStartupInput, NULL);

	IStream* stream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != 0)
	{
		printf("fail\n");
		return NULL;
	}

	bmp = Gdiplus::Bitmap::FromHBITMAP(hBitmap, (HPALETTE)0);
	CLSID pngClsid;
	GetEncoderClsid(L"image/png", &pngClsid);

	Gdiplus::Status res = bmp->Save(stream, &pngClsid);
	if (res != 0)
	{
		return NULL;
	}

	ULARGE_INTEGER liSize;
	IStream_Size(stream, &liSize);

	DWORD len = liSize.LowPart;
	IStream_Reset(stream);
	data = (char*)malloc(len);
	*size = len;
	IStream_Read(stream, data, len);

	if (stream != NULL)
		stream->Release();

	if (bmp != NULL)
		delete bmp;

	// Close Gdiplus
	Gdiplus::GdiplusShutdown(gdipToken);

	// clean up
	SelectObject(hDC, old_obj);
	DeleteDC(hDC);
	ReleaseDC(NULL, hScreen);
	DeleteObject(hBitmap);

	CoUninitialize();

	return data;
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



SystemInfo* Localhost::get_system_info()
{
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

std::list<Process> Localhost::list_processes()
{
	std::list<Process> proc_list;

	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	SYSTEM_INFO system_info;
	GetNativeSystemInfo(&system_info);

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG
		printf("CreateToolhelp32Snapshot error: INVALID HANDLE: %d\n", GetLastError());
#endif
		return proc_list;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
#ifdef DEBUG
		printf("Process32First error: %d\n", GetLastError());
#endif
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return proc_list;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		std::string proc_path = "";
		
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32;

		// Take a snapshot of all modules in the specified process.
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
#ifdef DEBUG
			printf("CreateToolhelp32Snapshot error: %d\n", GetLastError());
#endif

		}
		else 
		{
			// Set the size of the structure before using it.
			me32.dwSize = sizeof(MODULEENTRY32);

			// Retrieve information about the first module,
			// and exit if unsuccessful
			if (!Module32First(hModuleSnap, &me32))
			{
#ifdef DEBUG
				printf("Module32First error: %d\n", GetLastError());
#endif

				CloseHandle(hModuleSnap);           // clean the snapshot object
			}
			else
			{

				// Now walk the module list of the process,
				// and display information about each module
				do
				{
					if (strcmp(pe32.szExeFile, me32.szModule) == 0)
					{
						proc_path = std::string(me32.szExePath);

						break;
					}

				} while (Module32Next(hModuleSnap, &me32));

				CloseHandle(hModuleSnap);
			}

		}

		std::string image_type;
		if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			// Get process type
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL)
			{
				BOOL ImageType;
				BOOL success = IsWow64Process(hProcess, &ImageType);
				if (success == TRUE)
				{
					if (ImageType == TRUE)
					{
						image_type = "x32";
					}
					else
					{
						image_type = "x64";
					}
				}
				else
				{
					image_type = "unknown";
				}
			}
			else
			{
				image_type = "unknown";
			}
		}
		else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		{
			image_type = "x32";
		}
		else
		{
			image_type = "unknown";
		}


		proc_list.push_back(Process(pe32.szExeFile, proc_path.c_str(), pe32.th32ProcessID, pe32.th32ParentProcessID, image_type.c_str()));

		/*
		_tprintf(TEXT("\n\n====================================================="));
		_tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
		_tprintf(TEXT("\n-------------------------------------------------------"));
		*/

		/*
		_tprintf(TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID);
		_tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
		_tprintf(TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID);
		_tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
		if (dwPriorityClass)
			_tprintf(TEXT("\n  Priority class    = %d"), dwPriorityClass);
		*/


	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return proc_list;
}

std::list<Application> Localhost::list_applications()
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

std::list<RDPServer> Localhost::list_rdp_servers()
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

std::list<std::string> windows_list;

static BOOL CALLBACK enumWindowCallback(HWND hWnd, LPARAM lparam) {
	int length = GetWindowTextLength(hWnd);
	char* buffer = new char[length + 1];
	GetWindowText(hWnd, buffer, length + 1);
	std::string windowTitle(buffer);
	delete[] buffer;

	// List visible windows with a non-empty title
	if (IsWindowVisible(hWnd) && length != 0) {
		windows_list.push_back(windowTitle);
	}
	return TRUE;
}

std::list<std::string> Localhost::list_windows()
{
	windows_list.clear();

	EnumWindows(enumWindowCallback, NULL);

	return windows_list;
}

std::list<MountPoint> Localhost::list_mounts()
{
	std::list<MountPoint> mountpoint_list;

	PSHARE_INFO_502 BufPtr, pth;
	//PSHARE_INFO_2 BufPtr, pth;
	NET_API_STATUS  res;
	DWORD er = 0, tr = 0, resume = 0, I;

	// Call the NetShareEnum() function; specify level 502.
	do // begin do
	{
		res = NetShareEnum(NULL, 502, (LPBYTE*)&BufPtr, -1, &er, &tr, &resume);

		// If the call succeeds,
		if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
		{
			pth = BufPtr;
			// Loop through the entries, print the retrieved data.
			for (unsigned int i = 1; i <= er; i++)
			{
				MountPoint share_info = MountPoint(pth->shi502_netname, pth->shi502_path);

				mountpoint_list.push_back(share_info);

				pth++;
			}

			// Free the allocated buffer.
			NetApiBufferFree(BufPtr);
		}
	} while (res == ERROR_MORE_DATA); // end do

	return mountpoint_list;
}

std::list<VaultEntry> Localhost::list_vault()
{
	std::list<VaultEntry> vault_list;

	DWORD Count;
	PCREDENTIALW* Credential;
	//Now enumerate all http stored credentials....
	if (CredEnumerateW(NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &Count, &Credential))
	{

		for (int i = 0; i < Count; i++)
		{
			std::wstring username;
			if (Credential[i]->UserName != NULL)
				username = std::wstring(Credential[i]->UserName);
			else
				username = L"";
			std::wstring target;
			if (Credential[i]->TargetName != NULL)
				target = std::wstring(Credential[i]->TargetName);
			else
				target = L"";
			std::wstring comment;
			if (Credential[i]->Comment != NULL)
				comment = std::wstring(Credential[i]->Comment);
			else
				comment = L"";
			std::wstring password;
			if (Credential[i]->CredentialBlobSize != 0)
				password = std::wstring((wchar_t*)Credential[i]->CredentialBlob, Credential[i]->CredentialBlobSize / sizeof(wchar_t));
			else
				password = L"";

			vault_list.push_back(VaultEntry(target, username, comment, password));
		}
		CredFree(Credential);
	}

	return vault_list;
}

VaultEntry::VaultEntry(std::wstring target, std::wstring username, std::wstring comment, std::wstring password)
{
	this->target = target;
	this->username = username;
	this->comment = comment;
	this->password = password;
}

MountPoint::MountPoint(std::wstring name, std::wstring path)
{
	this->name = name;
	this->path = path;
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

Process::Process(const char* exe_name, const char* exe_path, unsigned int pid, unsigned int parent_pid, const char* image_type)
{
	this->exe_name = std::string(exe_name);
	this->exe_path = std::string(exe_path);
	this->pid = pid;
	this->parent_pid = parent_pid;
	this->image_type = std::string(image_type);
}