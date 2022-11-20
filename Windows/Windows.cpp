/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include <iostream>
#include "../lib/host.h"
#include "../lib/windows_host.h"

void scan_server(const char* ip)
{
    Host host = Host(ip);

    if (host.ping())
    {
        printf("%s responded to ping\n", ip);
    }
    else
    {
        printf("%s did not respond to ping\n", ip);
    }

    if (host.port_open(445))
    {
        printf("%s:%d is opened\n", ip, 445);
    }
    else
    {
        printf("%s:%d is not opened\n", ip, 445);
    }

    std::string* rdns = host.reverse_dns();
    if (rdns != NULL)
    {
        printf("Reverse DNS %s => %s\n", ip, rdns->c_str());

        delete rdns;
    }
    else
    {
        printf("Unable to perform reverse DNS\n");
    }

}

void list_shares(const char* ip)
{
    WindowsHost host = WindowsHost(ip);

    SystemInfo* system_info = host.getSystemInfo();
    if (system_info != NULL)
    {
        wprintf(L"Computer Name: %s\n", system_info->computername.c_str());
        wprintf(L"OS version: %s\n", system_info->os_version.c_str());
        wprintf(L"LAN group: %s\n", system_info->langroup.c_str());
        wprintf(L"LAN root: %s\n", system_info->lanroot.c_str());
    }
    else
    {
        printf("Unable to get system info: %d\n", GetLastError());
    }

    SetLastError(0);
    std::list<Share>* shares = host.shares();
    if (shares != NULL)
    {
        printf("Shares of %s:\n", ip);
        for (std::list<Share>::const_iterator iterator = shares->begin(), end = shares->end(); iterator != end; ++iterator) {
            Share share = (*iterator);

            wprintf(L" - %s %s (%s)\n", share.name.c_str(), share.local_path.c_str(), share.comment.c_str());
        }
    }
    else
    {
        printf("Unable to list shares: %d\n", GetLastError());
    }
}


int main()
{
    const char* ip = "192.168.0.151";

    WindowsHost host = WindowsHost(ip);
    host.deauth("\\\\192.168.0.151");

    scan_server(ip);

    list_shares(ip);

    host.auth("\\\\192.168.0.151", "domain.local\\user", "password");

    list_shares(ip);

    host.deauth("\\\\192.168.0.151");

    char* output = NULL;
    host.RCE_wmi_output(&output, "ipconfig", "domain.local\\user", "password", (size_t)(30 * 1000));
    if (output != NULL)
        printf("> %s\n", output);

    free(output);

    output = NULL;
    host.RCE_svc_output(&output, "whoami", "domain.local\\user", "password", (size_t)(30 * 1000));
    if(output != NULL)
        printf("> %s\n", output);

    free(output);
}

