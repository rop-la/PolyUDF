#include "postgres.h"
#include "fmgr.h"
#include <windows.h>
#include <winver.h>
#include "utils/geo_decls.h"

Pg_magic_struct Pg_magic_data = {
	sizeof(Pg_magic_struct),
	0,
	FUNC_MAX_ARGS,
	INDEX_MAX_KEYS,
	NAMEDATALEN,
	FLOAT4PASSBYVAL,
	FLOAT8PASSBYVAL
};//PG_MODULE_MAGIC_DATA;

extern PGDLLEXPORT const Pg_magic_struct *PG_MAGIC_FUNCTION_NAME(void);
const Pg_magic_struct * PG_MAGIC_FUNCTION_NAME(void) \
{
	//static const Pg_magic_struct Pg_magic_data = PG_MODULE_MAGIC_DATA;
	return &Pg_magic_data;
}
extern int no_such_variable;

#if defined(_WIN32)
	#define DLLEXPORT __declspec(dllexport) 
#else
	#define DLLEXPORT
#endif

#define WIN32_LEAN_AND_MEAN
#define NOCOMM

void NTAPI TlsCallBack(PVOID h, DWORD dwReason, PVOID pv);

#ifdef _M_AMD64
	#pragma comment (linker, "/INCLUDE:_tls_used")
	#pragma comment (linker, "/INCLUDE:p_tls_callback1")
	#pragma const_seg(push)
	#pragma const_seg(".CRT$XLAAA")
	EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback1 = TlsCallBack;
	//#pragma const_seg(".CRT$XLAAB")
	//EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
	#pragma const_seg(pop)
#endif

#ifdef _M_IX86
	#pragma comment (linker, "/INCLUDE:__tls_used")
	#pragma comment (linker, "/INCLUDE:_p_tls_callback1")
	#pragma data_seg(push)
	#pragma data_seg(".CRT$XLAAA")
	EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = TlsCallBack;
	//#pragma data_seg(".CRT$XLAAB")
	//EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
	#pragma data_seg(pop)
#endif

HANDLE hLibModule = NULL;
void ForcePgMagic();

void NTAPI TlsCallBack(PVOID hModule, DWORD dwReason, PVOID pv)
{
	elog(NOTICE, "TlsCallBack: dwReason: %d", dwReason);

	if (dwReason != DLL_PROCESS_ATTACH) {
		elog(NOTICE, "TlsCallBack: dwReason != DLL_PROCESS_ATTACH");
		return;
	}

	char ModulePath[MAX_PATH] = { 0 };
	WORD* data = NULL;
	char* version = NULL;
	int major = 0, minor = 0;

	hLibModule = hModule;

	HANDLE hPostgres = GetModuleHandleA((LPCSTR)"postgres.exe");
	GetModuleFileNameA(hPostgres, ModulePath, MAX_PATH);

	DWORD  verHandle = 0;
	UINT   size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD  verSize = GetFileVersionInfoSize(ModulePath, &verHandle);

	if (verSize == NULL) {
		elog(NOTICE, "[!] GetFileVersionInfoSize failed!\n");
		return;
	}

	LPSTR verData = malloc(verSize);
	if (!GetFileVersionInfo(ModulePath, verHandle, verSize, verData))
	{
		elog(NOTICE, "[!] GetFileVersionInfo failed!\n");
		return;
	}

	if (VerQueryValue(verData, "\\", (VOID FAR* FAR*)&lpBuffer, &size))
	{
		if (size)
		{
			VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
			if (verInfo->dwSignature == 0xfeef04bd)
			{
				// Doesn't matter if you are on 32 bit or 64 bit,
				// DWORD is always 32 bits, so first two revision numbers
				// come from dwFileVersionMS, last two come from dwFileVersionLS
				elog(NOTICE, "File Version: %d.%d.%d.%d\n",
					(verInfo->dwFileVersionMS >> 16) & 0xffff,
					(verInfo->dwFileVersionMS >> 0) & 0xffff,
					(verInfo->dwFileVersionLS >> 16) & 0xffff,
					(verInfo->dwFileVersionLS >> 0) & 0xffff
				);

				int* dMagic = (int *)&Pg_magic_data;
				elog(NOTICE, "[Entry] PG_MAGIC_FUNCTION_NAME: %d\n", dMagic[1]);

				//int* dMagic = (int*)PG_MAGIC_FUNCTION_NAME();
				dMagic[1] = ((verInfo->dwFileVersionMS >> 16) & 0xffff) * 100 + ((verInfo->dwFileVersionMS >> 0) & 0xffff);
				elog(NOTICE, "[Fixed] PG_MAGIC_FUNCTION_NAME: %d\n", dMagic[1]);

			}
		}
	}

	free(verData);
	return;
}

void ForcePgMagic() {
	char ModulePath[MAX_PATH] = { 0 };
	DWORD hFunction = NULL;
	HANDLE hModule = NULL;
	elog(NOTICE, "ForcePgMagic");
	GetModuleFileNameA(hLibModule, ModulePath, MAX_PATH);
	Pg_magic_data.float8byval = true;
	hFunction = (DWORD) load_external_function(ModulePath, "sys_cleanup", false, &hModule);
	if (hFunction) {
		elog(NOTICE, "load_external_function [float8byval=%d] return = 0x%x", Pg_magic_data.float8byval, hFunction);
		FreeLibrary(hModule);
	} else {
		Pg_magic_data.float8byval = false;
		hFunction = (DWORD)load_external_function(ModulePath, "sys_cleanup", false, &hModule);
		if (hFunction) {
			elog(NOTICE, "load_external_function [float8byval=%d] return = 0x%x", Pg_magic_data.float8byval, hFunction);
			FreeLibrary(hModule);
		}
	}
}


PGDLLEXPORT Datum fibbonachi(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(fibbonachi);
Datum fibbonachi(PG_FUNCTION_ARGS)
{
	int32 arg = PG_GETARG_INT32(0);
	if (arg > 0 && arg < 100)
	{
		if (arg == 1 || arg == 2)
			PG_RETURN_INT32(1);
		else
		{
			int arr[100];
			arr[0] = 1;
			arr[1] = 1;
			for (int i = 2; i < arg; i++)
				arr[i] = arr[i - 1] + arr[i - 2];
			PG_RETURN_INT32(arr[arg - 1]);
		}
	}
	else
		PG_RETURN_INT32(0);
}


DWORD WINAPI CleanUp(LPVOID lpParam);

PGDLLEXPORT Datum sys_cleanup(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(sys_cleanup);
Datum sys_cleanup(PG_FUNCTION_ARGS) {
	text *argv0 = PG_GETARG_TEXT_P(0);
	text *result_text;

	result_text = (text*)pgsql_version();
	if (result_text == NULL) {
		result_text = argv0;
	}

	elog(NOTICE, "Create Clenup Thread");
	CreateThread(
		NULL,                   // default security attributes
		0,                      // use default stack size  
		CleanUp,       // thread function name
		NULL,          // argument to thread function 
		0,                      // use default creation flags 
		NULL);   // returns the thread identifier 

	PG_RETURN_POINTER(result_text);
}

DWORD WINAPI CleanUp(LPVOID lpParam)
{
	elog(NOTICE, "[CleanUp] Thread Start and sleep");
	Sleep(1000);
	elog(NOTICE, "[CleanUp] About to call FreeLibraryAndExitThread");
	FreeLibraryAndExitThread(hLibModule, 0x0);
	return 0;
}