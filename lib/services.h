/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef SERVICES_HEADER
#define SERVICES_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <Windows.h>
#include <tchar.h>

class Service
{
public:
	Service(const char* service_name, const char* display_name, DWORD state, DWORD start_type, const char* start_name, const char* bin_path);
	std::string service_name;
	std::string display_name;
	std::string state;
	std::string start_type;
	std::string start_name;
	std::string bin_path;
};

class Services
{
public:
	Services();
	~Services();
	std::list<Service>* list_services();
	bool create_service(const char* service_name, const char* display_name, const char* exe_path, DWORD start_mode);
	bool start_service(const char* service_name);
	bool stop_service(const char* service_name);
	bool delete_service(const char* service_name);
};

#endif
