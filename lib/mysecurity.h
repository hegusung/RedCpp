//  @snowytoxa (c) 2013

// Source: https://github.com/snowytoxa/selfhash

#define SECURITY_WIN32
#define SEC_SUCCESS(Status) ((Status) >= 0)
#include <sspi.h>
#include <Secext.h>
#include <Security.h>
#include <string>

extern void PrintHexDump(DWORD length, PBYTE buffer);
void PrintHex(DWORD length, PBYTE buffer);
extern void MyHandleError(char *s);
std::string HextoString(DWORD length, PBYTE buffer);

