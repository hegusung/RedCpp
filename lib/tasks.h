/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef TASKS_HEADER
#define TASKS_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <vector>
#include <Windows.h>
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#include "com.h"


#pragma comment(lib, "taskschd.lib")
//#pragma comment(lib, "comsupp.lib")


class Task
{
public:
	Task(std::wstring task_folder, std::wstring task_name, TASK_STATE task_state, std::wstring task_description, std::wstring task_action);
	std::wstring task_folder;
	std::wstring task_name;
	std::wstring task_state;
	std::wstring task_description;
	std::wstring task_action;
};

class Tasks
{
public:
	Tasks(const wchar_t* hostname=NULL, const wchar_t* domain = NULL, const wchar_t* username = NULL, const wchar_t* password = NULL);
	~Tasks();
	std::list<Task>* list_tasks();
	void list_task_subfolder(ITaskFolder* rootFolder, HRESULT hr, std::wstring folder, std::list<Task>* task_list);
	bool create_task(std::wstring task_folder, std::wstring task_name, std::wstring exe_path);
	bool create_task_boot(std::wstring task_folder, std::wstring task_name, std::wstring exe_path);
	bool create_task_logon(std::wstring task_folder, std::wstring task_name, std::wstring exe_path, std::string domain_username);
	bool delete_task(std::wstring task_folder, std::wstring task_name);
	bool start_task(std::wstring task_folder, std::wstring task_name);
	bool stop_task(std::wstring task_folder, std::wstring task_name);
	/*
	bool create_service(const char* service_name, const char* display_name, const char* exe_path, DWORD start_mode);
	bool start_service(const char* service_name);
	bool stop_service(const char* service_name);
	bool delete_service(const char* service_name);
	*/
private:
	COM com;
	const wchar_t* w_hostname;
	const wchar_t* w_username;
	const wchar_t* w_domain;
	const wchar_t* w_password;
};

#endif
