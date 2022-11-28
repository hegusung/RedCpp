/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef COM_HEADER
#define COM_HEADER

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <list>
#include <string>
#include <comdef.h>

class COM
{
public:
	COM();
	~COM();
	bool initializeCom();
	bool CreateInstance(IID rclsid, IID riid, LPVOID* ppv, const wchar_t* host, const wchar_t* domain, const wchar_t* username, const wchar_t* password);
};


#endif
