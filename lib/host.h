/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#ifndef HOST_HEADER
#define HOST_HEADER

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <comdef.h>
#include <windns.h>
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib") //To link the winsock library
#pragma comment(lib, "Dnsapi.lib")

class Host
{
public:
	Host(const char* ip);
	~Host();
	bool ping();
	bool port_open(int port);
	std::string* reverse_dns();
private:
	std::string ip;
};

#endif