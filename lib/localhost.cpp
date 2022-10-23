#include "localhost.h"

Localhost::Localhost() {}

Localhost::~Localhost() {}

std::list<std::string> Localhost::listSubkeys(const char* reg_path)
{
	std::list<std::string> subkeys;

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
	LONG lResult = RegOpenKey(HKEY_LOCAL_MACHINE, reg_path, &hKey);
	if(lResult != ERROR_SUCCESS)
	{
		return subkeys;
	}

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
					subkeys.push_back(std::string(reg_path) + std::string("\\") + std::string(achKey));
				}
			}
		} 
	}

	return subkeys;
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



SystemInfo Localhost::getSystemInfo()
{
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);

	OSVERSIONINFOEX osinfo;
	osinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
#pragma warning(suppress : 4996)
	GetVersionEx((LPOSVERSIONINFO)&osinfo);

	return SystemInfo(siSysInfo.wProcessorArchitecture, siSysInfo.dwNumberOfProcessors, osinfo.dwMajorVersion, osinfo.dwMinorVersion, osinfo.dwBuildNumber, osinfo.wProductType);
}


std::list<Application> Localhost::getApplications()
{
	std::list<Application> apps_list;

	const char* reg_path = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

	std::list<std::string> reg_keys = this->listSubkeys(reg_path);

	std::list<std::string>::const_iterator it;
	for (it = reg_keys.begin(); it != reg_keys.end(); it++)
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

	reg_path = "Software\\Microsoft\\Windows\\CurrentVersion‌​\\Uninstall";

	reg_keys = this->listSubkeys(reg_path);

	for (it = reg_keys.begin(); it != reg_keys.end(); it++)
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

	return apps_list;
}

std::list<RDPServer> Localhost::getRDPServers()
{
	std::list<RDPServer> rdp_list;

	const char* reg_path = "Software\Microsoft\Terminal Server Client\Servers";

	std::list<std::string> reg_keys = this->listSubkeys(reg_path);

	std::list<std::string>::const_iterator it;
	for (it = reg_keys.begin(); it != reg_keys.end(); it++)
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

	return rdp_list;
}

SystemInfo::SystemInfo(WORD wProcessorArchitecture, DWORD dwNumberOfProcessors, DWORD dwMajorVersion, DWORD dwMinorVersion, DWORD dwBuildNumber, DWORD wProductType)
{
	if (wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		this->proc_arch = std::string("x64");
	}
	else if (wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM)
	{
		this->proc_arch = std::string("ARM");
	}
	else if (wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		this->proc_arch = std::string("Intel Itanium-based");
	}
	else if (wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
	{
		this->proc_arch = std::string("x86");
	}
	else if (wProcessorArchitecture == PROCESSOR_ARCHITECTURE_UNKNOWN)
	{
		this->proc_arch = std::string("Unknown architecture: ") + std::to_string(wProcessorArchitecture);
	}

	this->nb_procs = (unsigned int)dwNumberOfProcessors;

	this->win_version = std::string("");
	if (dwMajorVersion == 5)
	{
		if (dwMinorVersion == 0)
		{
			this->win_version = std::string("Windows 2000");
		}
		else if (dwMinorVersion == 1)
		{
			this->win_version = std::string("Windows XP");
		}
		else if (dwMinorVersion == 2)
		{
			this->win_version = std::string("Windows Server 2003");
		}
	}
	else if (dwMajorVersion == 6)
	{
		if (dwMinorVersion == 0)
		{
			if (wProductType == VER_NT_WORKSTATION)
			{
				this->win_version = std::string("Windows Vista");
			}
			else
			{
				this->win_version = std::string("Windows Server 2008");
			}
		}
		else if (dwMinorVersion == 1)
		{
			if (wProductType == VER_NT_WORKSTATION)
			{
				this->win_version = std::string("Windows 7");
			}
			else
			{
				this->win_version = std::string("Windows Server 2008 R2");
			}
		}
		else if (dwMinorVersion == 2)
		{
			if (wProductType == VER_NT_WORKSTATION)
			{
				this->win_version = std::string("Windows 8");
			}
			else
			{
				this->win_version = std::string("Windows Server 2012");
			}
		}
		else if (dwMinorVersion == 3)
		{
			if (wProductType == VER_NT_WORKSTATION)
			{
				this->win_version = std::string("Windows 8.1");
			}
			else
			{
				this->win_version = std::string("Windows Server 2012 R2");
			}
		}
	}
	else if (dwMajorVersion == 10)
	{
		if (dwMinorVersion == 0)
		{
			if (wProductType == VER_NT_WORKSTATION)
			{
				this->win_version = std::string("Windows 10");
			}
			else
			{
				this->win_version = std::string("Windows Server 2016");
			}
		}
	}

	if (this->win_version.size() == 0)
	{
		this->win_version = std::string("Unknown version: ") + std::to_string(dwMajorVersion) + "." + std::to_string(dwMinorVersion);
	}

	this->win_version += std::string(" Build ") + std::to_string(dwBuildNumber);
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