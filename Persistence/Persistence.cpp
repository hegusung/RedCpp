// Persistence.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <sstream>
#include <list>
#include "../lib/registry.h"
#include "../lib/services.h"
#include "../lib/tasks.h"
#include "../lib/links.h"
#include "../lib/wmi.h"

void set_run_key_persistence()
{
	HKEY root = HKEY_CURRENT_USER;
	const char* key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	Registry reg = Registry();
	bool success;

	success = reg.set_entry_sz(key, "Test", "C:\\test.exe");
	if (success)
	{
		printf("Successfully set registry key\n");
	}
	else
	{
		printf("Failed to set registry key\n");
	}

	success = reg.set_entry_multi_sz(key, "Test2", "test1,test2,test3");
	if (success)
	{
		printf("Successfully set registry key\n");
	}
	else
	{
		printf("Failed to set registry key\n");
	}

	success = reg.set_entry_dword(key, "Test3", 42);
	if (success)
	{
		printf("Successfully set registry key\n");
	}
	else
	{
		printf("Failed to set registry key\n");
	}

	printf("%s registry subkeys:\n", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion");
	std::list<std::string>* subkey_list = reg.list_registry_subkeys("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion");
	if (subkey_list != NULL)
	{
		for (std::list<std::string>::const_iterator iterator = subkey_list->begin(), end = subkey_list->end(); iterator != end; ++iterator) {

			printf(" - %s\n", (*iterator).c_str());
		}

		delete subkey_list;
	}
	else
	{
		printf("Failed to list sub keys\n");
	}

	printf("%s registry keys:\n", key);
	std::list<RegEntry>* reg_list = reg.list_registry_entries(key);
	if (reg_list != NULL)
	{
		for (std::list<RegEntry>::const_iterator iterator = reg_list->begin(), end = reg_list->end(); iterator != end; ++iterator) {

			if ((*iterator).type.compare("REG_BINARY") == 0)
			{
				std::stringstream sstream;
				//std::string data = "";
				for (int i = 0; i < (*iterator).value.size(); i++)
				{
					sstream << std::hex << (int)((*iterator).value.c_str()[i]) << " ";
					//printf("> %d\n", (*iterator).value.c_str()[i]);
					//data += " " + std::to_string((*iterator).value.c_str()[i]);
				}
				printf(" - %s (%s): %s\n", (*iterator).name.c_str(), (*iterator).type.c_str(), sstream.str().c_str());
			}
			else
				printf(" - %s (%s): %s\n", (*iterator).name.c_str(), (*iterator).type.c_str(), (*iterator).value.c_str());
		}

		delete reg_list;
	}
	else
	{
		printf("Failed to list reg keys\n");
	}

	success = reg.remove_entry(key, "Test");
	if (success)
	{
		printf("Successfully removed registry key\n");
	}
	else
	{
		printf("Failed to remove registry key\n");
	}

	success = reg.remove_entry(key, "Test2");
	if (success)
	{
		printf("Successfully removed registry key\n");
	}
	else
	{
		printf("Failed to remove registry key\n");
	}

	success = reg.remove_entry(key, "Test3");
	if (success)
	{
		printf("Successfully removed registry key\n");
	}
	else
	{
		printf("Failed to remove registry key\n");
	}
}

void list_com()
{
	Registry reg = Registry();

	printf("COM objects:\n");
	std::list<COM>* com_list = reg.list_com();
	if (com_list != NULL)
	{
		for (std::list<COM>::const_iterator iterator = com_list->begin(), end = com_list->end(); iterator != end; ++iterator) {

			printf(" - %s: %s\n", (*iterator).clsid.c_str(), (*iterator).name.c_str());
		}

		delete com_list;
	}
	else
	{
		printf("Failed to list COM objects\n");
	}
}

void set_service_persistence()
{
	Services services = Services();

	bool success = services.create_service("Test", "Test service", "C:\\test.exe", SERVICE_AUTO_START);
	if (success)
	{
		printf("Successfully created service\n");
	}
	else
	{
		printf("Failed to create service\n");
	}

	printf("Services:\n");
	std::list<Service>* list_service = services.list_services();
	if (list_service != NULL)
	{
		for (std::list<Service>::const_iterator iterator = list_service->begin(), end = list_service->end(); iterator != end; ++iterator) {

			printf(" - %s (%s)\n", (*iterator).service_name.c_str(), (*iterator).display_name.c_str());
			printf("     State     : %s\n", (*iterator).state.c_str());
			printf("     Start type: %s\n", (*iterator).start_type.c_str());
			printf("     Start name: %s\n", (*iterator).start_name.c_str());
			printf("     Bin path  : %s\n", (*iterator).bin_path.c_str());
		}

		delete list_service;
	}
	else
	{
		printf("Failed to list services\n");
	}

	success = services.start_service("Test");
	if (success)
	{
		printf("Successfully started service\n");
	}
	else
	{
		printf("Failed to start service\n");
	}

	success = services.stop_service("Test");
	if (success)
	{
		printf("Successfully stopped service\n");
	}
	else
	{
		printf("Failed to stop service\n");
	}

	success = services.delete_service("Test");
	if (success)
	{
		printf("Successfully deleted service\n");
	}
	else
	{
		printf("Failed to delete service\n");
	}
}

void set_task_persistence()
{
	Tasks tasks = Tasks();

	bool success = tasks.create_task(L"\\", L"Test task", L"C:\\Windows\\System32\\calc.exe");
	if (success)
	{
		printf("Successfully created task\n");
	}
	else
	{
		printf("Failed to create task\n");
	}

	printf("Tasks:\n");
	std::list<Task>* task_list = tasks.list_tasks();
	if (task_list != NULL)
	{
		for (std::list<Task>::const_iterator iterator = task_list->begin(), end = task_list->end(); iterator != end; ++iterator) {

			wprintf(L" - %s (%s)\n", (*iterator).task_name.c_str(), (*iterator).task_folder.c_str());
			wprintf(L"     State      : %s\n", (*iterator).task_state.c_str());
			wprintf(L"     Description: %s\n", (*iterator).task_description.c_str());
			wprintf(L"     Action     : %s\n", (*iterator).task_action.c_str());
		}

		delete task_list;
	}
	else
	{
		printf("Failed to list services\n");
	}

	success = tasks.start_task(L"\\", L"Test task");
	if (success)
	{
		printf("Successfully started task\n");
	}
	else
	{
		printf("Failed to start task: %d\n", GetLastError());
	}

	success = tasks.stop_task(L"\\", L"Test task");
	if (success)
	{
		printf("Successfully stopped task\n");
	}
	else
	{
		printf("Failed to stop task: %d\n", GetLastError());
	}

	success = tasks.delete_task(L"\\", L"Test task");
	if (success)
	{
		printf("Successfully deleted task\n");
	}
	else
	{
		printf("Failed to delete task\n");
	}
}

void set_link_persistence()
{
	Links links = Links();

	bool success = links.create_startup_folder_link("Test", "Test task", "C:\\test.exe", "");
	if (success)
	{
		printf("Successfully created startup folder link\n");
	}
	else
	{
		printf("Failed to create startup folder link: %d\n", GetLastError());
	}
	
	char* buf = nullptr;
	size_t sz = 0;
	if (_dupenv_s(&buf, &sz, "USERPROFILE") == 0 && buf != nullptr)
	{
		std::string userpath = std::string(buf);

		printf("Links:\n");
		std::list<Link>* link_list = links.list_links(userpath, true);
		if (link_list != NULL)
		{
			for (std::list<Link>::const_iterator iterator = link_list->begin(), end = link_list->end(); iterator != end; ++iterator) {

				printf(" - %s\n", (*iterator).lnk_path.c_str());
				printf("     Description: %s\n", (*iterator).lnk_description.c_str());
				printf("     Target     : %s\n", (*iterator).lnk_target.c_str());
				printf("     Args       : %s\n", (*iterator).lnk_args.c_str());
			}

			delete link_list;
		}
		else
		{
			printf("Failed to list services\n");
		}

		free(buf);
	}

	success = links.remove_startup_folder_link("Test");
	if (success)
	{
		printf("Successfully deleted startup folder link\n");
	}
	else
	{
		printf("Failed to delete startup folder link: %d\n", GetLastError());
	}
}

void set_wmi_persistence()
{
	WMI wmi;
	bool success;

	const wchar_t* filter_name = L"filter1";
	const wchar_t* consumer_name = L"consumer1";

	success = wmi.persistence(filter_name, consumer_name, L"C:\\test.exe");
	if (success)
	{
		printf("Successfully set up wmi persistence\n");
	}
	else
	{
		printf("Failed to set up wmi persistence: %d\n", GetLastError());
	}

	printf("=========================================================\n");
	printf("============ Event filters ==============================\n");

	std::list<Object>* object_list = wmi.list_event_filters();
	if (object_list != NULL)
	{
		for (std::list<Object>::const_iterator iterator = object_list->begin(), end = object_list->end(); iterator != end; ++iterator) {

			printf("=========================================================\n");

			for (std::list<Entry>::const_iterator iterator2 = (*iterator).entry_list.begin(), end2 = (*iterator).entry_list.end(); iterator2 != end2; ++iterator2) {

				wprintf(L" - %s (%s): %s\n", (*iterator2).name.c_str(), (*iterator2).type.c_str(), (*iterator2).value.c_str());
			}
		}

		delete object_list;
	}
	else
	{
		printf("Failed to list envent filters\n");
	}

	printf("=========================================================\n");
	printf("============ Event consumers ============================\n");

	object_list = wmi.list_event_consumers();
	if (object_list != NULL)
	{
		for (std::list<Object>::const_iterator iterator = object_list->begin(), end = object_list->end(); iterator != end; ++iterator) {

			printf("=========================================================\n");

			for (std::list<Entry>::const_iterator iterator2 = (*iterator).entry_list.begin(), end2 = (*iterator).entry_list.end(); iterator2 != end2; ++iterator2) {

				wprintf(L" - %s (%s): %s\n", (*iterator2).name.c_str(), (*iterator2).type.c_str(), (*iterator2).value.c_str());
			}
		}

		delete object_list;
	}
	else
	{
		printf("Failed to list event consumers\n");
	}

	printf("=========================================================\n");
	printf("============ Event filter 2 consumers ===================\n");

	object_list = wmi.list_event_filter_to_consumers();
	if (object_list != NULL)
	{
		for (std::list<Object>::const_iterator iterator = object_list->begin(), end = object_list->end(); iterator != end; ++iterator) {

			printf("=========================================================\n");

			for (std::list<Entry>::const_iterator iterator2 = (*iterator).entry_list.begin(), end2 = (*iterator).entry_list.end(); iterator2 != end2; ++iterator2) {

				wprintf(L" - %s (%s): %s\n", (*iterator2).name.c_str(), (*iterator2).type.c_str(), (*iterator2).value.c_str());
			}
		}

		delete object_list;
	}
	else
	{
		printf("Failed to list event filter2consumers\n");
	}

	success = wmi.delete_persistence(filter_name, consumer_name);
	if (success)
	{
		printf("Successfully deleted wmi persistence\n");
	}
	else
	{
		printf("Failed to delete wmi persistence: %d\n", GetLastError());
	}

	/*
	success = wmi.delete_event_filter(filter_name);
	if (success)
	{
		printf("Successfully deleted event filter\n");
	}
	else
	{
		printf("Failed to delete event filter: %d\n", GetLastError());
	}

	success = wmi.delete_event_consumer(consumer_name);
	if (success)
	{
		printf("Successfully deleted event consumer\n");
	}
	else
	{
		printf("Failed to delete event consumer: %d\n", GetLastError());
	}
	*/
}


int main()
{
	//list_com();

	//set_run_key_persistence();

	/*
	printf("\n==========================================\n\n");

	set_service_persistence();

	printf("\n==========================================\n\n");

	set_task_persistence();

	printf("\n==========================================\n\n");
	*/
	//set_link_persistence();

	printf("\n==========================================\n\n");

	set_wmi_persistence();
}