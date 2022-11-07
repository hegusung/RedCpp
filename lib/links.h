/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef LINKS_HEADER
#define LINKS_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <Windows.h>
#include <shobjidl.h>
#include <shlguid.h>
#include <strsafe.h>
#include <KnownFolders.h>
#include <ShlObj_core.h>

class Link
{
public:
	Link(const char* lnk_path, const char* lnk_description, const char* lnk_target, const char* lnk_args);
	std::string lnk_path;
	std::string lnk_description;
	std::string lnk_target;
	std::string lnk_args;
};

class Links
{
public:
	Links();
	~Links();
	std::list<Link>* list_links(std::string path, bool recursive);
	void list_links_in_subdir(std::string path, std::list<Link>* link_list, bool recursive);
	void get_link_info(std::string path, std::list<Link>* link_list);
	bool create_startup_folder_link(const char* lnk_name, const char* lnk_description, const char* lnk_target, const char* lnk_args);
	bool remove_startup_folder_link(const char* lnk_name);
	/*
	bool create_link(const char* service_name, const char* display_name, const char* exe_path, DWORD start_mode);
	bool delete_link(const char* service_name);
	*/
};

bool ends_with(std::wstring const& value, std::wstring const& ending);

#endif
