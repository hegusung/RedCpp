/*
* Github: https://github.com/stephenfewer/ReflectiveDLLInjection
*/

#ifndef REFLECTIVE_INJECTION_HEADER
#define REFLECTIVE_INJECTION_HEADER

#include <stdio.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// we declare some common stuff in here...

/*
#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
*/
#define DLL_QUERY_HMODULE		6

#define DLL_REFLECTIVE_FUNCTION "ReflectiveLoader"

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI* REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

BOOL InjectToProcess(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength);
DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer);
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength);
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);

#endif
