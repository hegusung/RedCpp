#ifndef SERVER
#define SERVER

// Source: https://github.com/snowytoxa/selfhash

#include <windows.h>
#include <string>

#define SECURITY_WIN32
#define SEC_SUCCESS(Status) ((Status) >= 0)
#include <sspi.h>
#include <Secext.h>
#include <Security.h>

#include "mysecurity.h"

#pragma comment(lib, "Secur32.lib")

class Hash
{
public:
	Hash(char* username, char* computer);
	void setNTLMv2(std::string nonce, std::string client_nonce, std::string nthash);
	void setNTLM(std::string nonce, std::string lmhash, std::string nthash);
	std::string username;
	std::string computer;
	// Common
	int type;  // 1 = NTLMv1, 2 = NTLMv2
	std::string nonce;
	std::string nthash;
	// NTLMv2
	std::string client_nonce;
	// NTLM
	std::string lmhash;
};

Hash* DoAuthentication();
BOOL GenServerContext (BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, BOOL fNewCredential, CredHandle *hcred, struct _SecHandle *hctxt);
BOOL GenClientContext (BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, SEC_CHAR *pszTarget, CredHandle *hCred, struct _SecHandle *hCtxt);


#endif