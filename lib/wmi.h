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
#include <Wbemidl.h>
#include <comdef.h>

# pragma comment(lib, "wbemuuid.lib")

class WMI
{
public:
	WMI();
	~WMI();
	bool initializeCom();
	bool execute(const char* host, const char* username, const char* password, const char* command);
	bool setUpWBEM(const char* host, const char* username, const char* password, IWbemLocator** wbemLocator, IWbemServices** wbemServices);
private:

};

#endif
