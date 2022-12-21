/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "services.h"

Services::Services(const char* hostname)
{
    this->hostname = hostname;
}

Services::~Services()
{
}

std::list<Service>* Services::list_services()
{
    std::list<Service>* service_list = NULL;

    void* buf = NULL;
    DWORD bufSize = 0;
    DWORD moreBytesNeeded, serviceCount;

    SC_HANDLE sc = OpenSCManagerA(this->hostname, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
    if (sc == NULL)
    {
#ifdef DEBUG
        printf("OpenSCManagerA failure: %d\n", GetLastError());
#endif
        return NULL;
    }

    for (;;) {

        if (EnumServicesStatusEx(
            sc,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            (LPBYTE)buf,
            bufSize,
            &moreBytesNeeded,
            &serviceCount,
            NULL,
            NULL)) 
        {
            service_list = new std::list<Service>();

            ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)buf;

            for (DWORD i = 0; i < serviceCount; ++i) {
                //printf("%s\n", services[i].lpServiceName);

                SC_HANDLE hService = OpenServiceA(sc, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (hService == NULL)
                {
                    service_list->push_back(Service(services[i].lpServiceName, services[i].lpDisplayName, services[i].ServiceStatusProcess.dwCurrentState, 10, "", ""));
                }
                else
                {
                    QUERY_SERVICE_CONFIGA service_config;
                    DWORD BytesNeeded = 0;
                    BOOL success = QueryServiceConfigA(hService, NULL, 0, &BytesNeeded);
                    if (success == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        LPQUERY_SERVICE_CONFIGA service_config = (LPQUERY_SERVICE_CONFIGA)malloc(BytesNeeded);

                        success = QueryServiceConfigA(hService, service_config, BytesNeeded, &BytesNeeded);
                        if(success == TRUE)
                        {
                            service_list->push_back(Service(services[i].lpServiceName, services[i].lpDisplayName, services[i].ServiceStatusProcess.dwCurrentState, service_config->dwStartType, service_config->lpServiceStartName, service_config->lpBinaryPathName));
                        }
                        else
                        {
                            service_list->push_back(Service(services[i].lpServiceName, services[i].lpDisplayName, services[i].ServiceStatusProcess.dwCurrentState, 10, "", ""));
                        }
                    }
                    else
                    {
                        service_list->push_back(Service(services[i].lpServiceName, services[i].lpDisplayName, services[i].ServiceStatusProcess.dwCurrentState, 10, "", ""));
                    }

                    CloseServiceHandle(hService);
                }

            }

            free(buf);

            break;
        }
        else
        {
            int err = GetLastError();
            if (ERROR_MORE_DATA != err) {
                CloseServiceHandle(sc);
                free(buf);
                return NULL;
            }
            bufSize += moreBytesNeeded;
            free(buf);
            buf = malloc(bufSize);
        }
    }

    CloseServiceHandle(sc);

    return service_list;
}

bool Services::create_service(const char* service_name, const char* display_name, const char* exe_path, DWORD start_mode)
{
    SC_HANDLE sc = OpenSCManagerA(this->hostname, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);
    if (sc == NULL)
    {
#ifdef DEBUG
        printf("OpenSCManagerA failure: %d\n", GetLastError());
#endif
        return false;
    }

    SC_HANDLE hService = CreateServiceA(sc, service_name, display_name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, start_mode, SERVICE_ERROR_IGNORE, exe_path, NULL, NULL, NULL, NULL, NULL);

    if (hService == NULL)
    {
        CloseServiceHandle(sc);
        return false;
    }
    else
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(sc);
        return true;
    }
}

bool Services::start_service(const char* service_name)
{
    SC_HANDLE sc = OpenSCManagerA(this->hostname, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (sc == NULL)
    {
#ifdef DEBUG
        printf("OpenSCManagerA failure: %d\n", GetLastError());
#endif
        return false;
    }

    SC_HANDLE hService = OpenServiceA(sc, service_name, SERVICE_START);
    if (hService == NULL)
    {
        CloseServiceHandle(sc);
        return false;
    }

    BOOL success = StartServiceA(hService, 0, NULL);

    CloseServiceHandle(hService);
    CloseServiceHandle(sc);

    if (success == TRUE)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool Services::stop_service(const char* service_name)
{
    SC_HANDLE sc = OpenSCManagerA(this->hostname, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (sc == NULL)
    {
#ifdef DEBUG
        printf("OpenSCManagerA failure: %d\n", GetLastError());
#endif
        return false;
    }

    SC_HANDLE hService = OpenServiceA(sc, service_name, SERVICE_STOP);
    if (hService == NULL)
    {
        CloseServiceHandle(sc);
        return false;
    }

    SERVICE_STATUS status;
    BOOL success = ControlService(hService, SERVICE_CONTROL_STOP, &status);

    CloseServiceHandle(hService);
    CloseServiceHandle(sc);

    if (success == TRUE)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool Services::delete_service(const char* service_name)
{
    SC_HANDLE sc = OpenSCManagerA(this->hostname, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (sc == NULL)
    {
#ifdef DEBUG
        printf("OpenSCManagerA failure: %d\n", GetLastError());
#endif
        return false;
    }

    SC_HANDLE hService = OpenServiceA(sc, service_name, DELETE);
    if (hService == NULL)
    {
        CloseServiceHandle(sc);
        return false;
    }

    SERVICE_STATUS status;
    BOOL success = DeleteService(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(sc);

    if (success == TRUE)
    {
        return true;
    }
    else
    {
        return false;
    }
}

Service::Service(const char* service_name, const char* display_name, DWORD state, DWORD start_type, const char* start_name, const char* bin_path)
{
    this->service_name = std::string(service_name);
    this->display_name = std::string(display_name);
    this->start_name = std::string(start_name);
    this->bin_path = std::string(bin_path);

    switch (state)
    {
    case SERVICE_STOPPED:
        this->state = std::string("stopped");
        break;
    case SERVICE_START_PENDING:
        this->state = std::string("start_pending");
        break;
    case SERVICE_STOP_PENDING:
        this->state = std::string("stop_pending");
        break;
    case SERVICE_RUNNING:
        this->state = std::string("running");
        break;
    case SERVICE_CONTINUE_PENDING:
        this->state = std::string("continue_pending");
        break;
    case SERVICE_PAUSE_PENDING:
        this->state = std::string("pause_pending");
        break;
    case SERVICE_PAUSED:
        this->state = std::string("paused");
        break;
    default:
        this->state = std::string("unknown");
    }

    switch (start_type)
    {
    case SERVICE_BOOT_START:
        this->start_type = std::string("boot_start");
        break;
    case SERVICE_SYSTEM_START:
        this->start_type = std::string("system_start");
        break;
    case SERVICE_AUTO_START:
        this->start_type = std::string("auto_start");
        break;
    case SERVICE_DEMAND_START:
        this->start_type = std::string("demand_start");
        break;
    case SERVICE_DISABLED:
        this->start_type = std::string("disabled");
        break;
    default:
        this->start_type = std::string("unknown");
    }
}