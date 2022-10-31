// Recon.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <list>
#include "../lib/net.h"

void list_groups()
{
	Net net = Net();

	printf("Global groups:\n");
	std::list<std::wstring> group_list = net.get_global_groups(NULL);
    for (std::list<std::wstring>::const_iterator iterator = group_list.begin(), end = group_list.end(); iterator != end; ++iterator) {
        wprintf(L" - %s", (*iterator).c_str());
    }

	printf("Local groups:\n");
	group_list = net.get_local_groups(NULL);
	for (std::list<std::wstring>::const_iterator iterator = group_list.begin(), end = group_list.end(); iterator != end; ++iterator) {
		wprintf(L" - %s", (*iterator).c_str());
	}
}

int main()
{
	list_groups();

	printf("\n==========================================\n\n");

	
}
