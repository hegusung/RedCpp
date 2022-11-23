/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef WMI_HEADER
#define WMI_HEADER

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <list>
#include <string>
#include <Wbemidl.h>
#include <comdef.h>

# pragma comment(lib, "wbemuuid.lib")


class Entry
{
public:
	Entry(const wchar_t* name, const wchar_t* type, std::wstring value);
	std::wstring name;
	std::wstring type;
	std::wstring value;
};

class Object
{
public:
	Object();
	void add(Entry entry);
	std::list<Entry> entry_list;
};

class WMI
{
public:
	WMI();
	~WMI();
	bool initializeCom();
	bool execute(const char* host, const char* username, const char* password, const char* command);
	bool setUpWBEM(const wchar_t* wmi_namespace, const char* host, const char* username, const char* password, IWbemLocator** wbemLocator, IWbemServices** wbemServices);
	bool persistence(const wchar_t* ef_class_name, const wchar_t* ec_class_name, const wchar_t* command);
	std::list<Object>* list_class_objects(const wchar_t* class_name);
	std::list<Object>* list_event_filters();
	std::list<Object>* list_event_consumers();
	std::list<Object>* list_event_filter_to_consumers();
	bool delete_object(const wchar_t* class_name, const wchar_t* instance_name);
	bool delete_persistence(const wchar_t* ef_class_name, const wchar_t* ec_class_name);
private:

};


#endif
