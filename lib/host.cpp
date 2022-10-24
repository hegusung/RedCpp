/*
* Author: Hegusung
* Github: https://github.com/hegusung/RedCpp
*/

#include "host.h"

Host::Host(const char* ip)
{
	this->ip = std::string(ip);
}

Host::~Host()
{
}

bool Host::ping()
{
	// Process 
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD exit_code;	
	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	// Start the child process. 
	if( !CreateProcess( NULL,   // No module name (use command line)
		(LPSTR)("cmd.exe /C \"ping -n 1 " + this->ip + " | find ^\"Reply from " + this->ip + ":^\"\"").c_str(),   // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_NO_WINDOW,              // Do not create a window
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi )           // Pointer to PROCESS_INFORMATION structure
	) 
	{
		#ifdef DEBUG
		printf("[Host::Ping] Createprocess failed: %d\n", GetLastError());
		#endif
		return false;
	}

	// Wait until child process exits.
	WaitForSingleObject( pi.hProcess, INFINITE );
	GetExitCodeProcess(pi.hProcess, &exit_code);
		
	if (exit_code == 0) 
	{
		#ifdef DEBUG
		printf("[Host::Ping] ping %s succeeded\n", this->ip.c_str());
		#endif
		return true;
	}
	else
	{
		#ifdef DEBUG
		printf("[Host::Ping] ping %s failed\n", this->ip.c_str());
		#endif
		return false;
	}
}

bool Host::port_open(int port)
{
	WSADATA firstsock;   
	SOCKET s;
	int err;
	struct sockaddr_in sa;

	strncpy_s((char *)&sa, sizeof(sockaddr_in), "", sizeof sa);
	sa.sin_family = AF_INET; //this line must be like this coz internet
 
	//Initialise winsock
	if (WSAStartup(MAKEWORD(2,0),&firstsock) != 0)  //CHECKS FOR WINSOCK VERSION 2.0
	{
		#ifdef DEBUG
		printf("[Host::Port] Error initialising socket: %d\n", GetLastError());
		#endif
		return false;
	} 

	s = socket(AF_INET , SOCK_STREAM , 0); //make net a valid socket handle
	if(s < 0)  //if not a socket
	{
		#ifdef DEBUG
		printf("[Host::Port] Error creating socket: %d\n", GetLastError());
		#endif
		return false;
	}

	sa.sin_port = htons(port);
	InetPton(AF_INET, this->ip.c_str(), &sa.sin_addr.s_addr);

	err = connect(s , (struct sockaddr *)&sa , sizeof sa);
	if(err == SOCKET_ERROR) //connection not accepted
	{
		closesocket(s);
		#ifdef DEBUG
		printf("[Host::Port] %s:%d closed\n", this->ip.c_str(), port);
		#endif
		return false;
	}
	else  //connection accepted
	{
		shutdown( s ,SD_BOTH );

		closesocket(s);
		#ifdef DEBUG
		printf("[Host::Port] %s:%d open\n", this->ip.c_str(), port);
		#endif
		return true;
	} 
}

std::string* Host::reverse_dns()
{
	// IP => RIP.IN-ADDR.ARPA
	char seps[]   = ".";
    char *token;
    char pIPSec[4][4];
    int i=0;
	char* next_token;
	rsize_t ip_size = this->ip.size();
    token = strtok_s((char*)this->ip.c_str(), seps, &next_token);
    while( token != NULL )
    {
        /* While there are "." characters in "string" */
        sprintf_s(pIPSec[i], 4, "%s", token);
        /* Get next "." character: */
        token = strtok_s( NULL, seps, &next_token);
        i++;
    }
	char* pIP = (char*)malloc(3*4+4+20);
    sprintf_s(pIP, 3 * 4 + 4 + 20, "%s.%s.%s.%s.%s", pIPSec[3],pIPSec[2],pIPSec[1],pIPSec[0],"IN-ADDR.ARPA");

	#ifdef DEBUG
	printf("[Host::reverse_dns] %s\n", pIP);
	#endif

	PDNS_RECORD query_data;
	DNS_FREE_TYPE freetype;
	freetype =  DnsFreeRecordListDeep;
	DNS_STATUS status = DnsQuery_A(pIP, DNS_TYPE_PTR, DNS_QUERY_STANDARD, NULL, &query_data, NULL);

	free(pIP);
	if(status == 0)
	{
		#ifdef DEBUG
		printf("[Host::rdns] Reverse DNS success %s => %s\n", this->ip.c_str(), query_data->Data.PTR.pNameHost);
		#endif

		std::string* rdns = new std::string(query_data->Data.PTR.pNameHost);

		DnsRecordListFree(query_data, freetype);
		return rdns;
	}
	else
	{
		#ifdef DEBUG
		printf("[Host::rdns] Reverse DNS failed: %d\n", status);
		#endif

		return NULL;
	}
}

