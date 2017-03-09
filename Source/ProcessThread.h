#ifndef CXX_ProcessThread_H
#define CXX_ProcessThread_H

#include <ntifs.h>

#include "Private.h"

typedef struct _PROCESS_THREAD_ENTRY_INFORMATION
{
	UINT_PTR EThread;
	UINT32   ThreadId;
	UINT_PTR Teb;
	UINT8    Priority;
	UINT_PTR Win32StartAddress;
	UINT32   ContextSwitches;
	UINT8    State;
} PROCESS_THREAD_ENTRY_INFORMATION, *PPROCESS_THREAD_ENTRY_INFORMATION;


typedef struct _PROCESS_THREAD_INFORMATION
{
	UINT32                           ThreadCount;
	PROCESS_THREAD_ENTRY_INFORMATION Threads[1];
} PROCESS_THREAD_INFORMATION, *PPROCESS_THREAD_INFORMATION;

typedef struct _THREAD_MODULE_ENTRY_INFORMATION
{
	UINT_PTR BaseAddress;
	UINT_PTR Size;
	WCHAR    wzFileFullPath[MAX_PATH];
} THREAD_MODULE_ENTRY_INFORMATION, *PTTHREAD_MODULE_ENTRY_INFORMATION;

typedef struct _THREAD_MODULE_INFORMATION
{
	UINT32                          ModuleCount;
	THREAD_MODULE_ENTRY_INFORMATION Modules[1];
} THREAD_MODULE_INFORMATION, *PTHREAD_MODULE_INFORMATION;


BOOLEAN
IsThreadInList(IN PETHREAD EThread, IN PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 ThreadCount);

UINT_PTR
GetThreadStartAddress(IN PETHREAD EThread);

VOID
FillProcessThreadInfo(IN PETHREAD EThread, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 ThreadCount);

NTSTATUS
EnumProcessThread(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength);

BOOLEAN
IsModuleInList(IN UINT_PTR BaseAddress, IN UINT32 ModuleSize, IN PTHREAD_MODULE_INFORMATION ThreadModule, IN UINT_PTR ModuleCount);

NTSTATUS
EnumDllModuleByPeb(IN PEPROCESS EProcess, OUT PTHREAD_MODULE_INFORMATION ThreadModule, UINT32 ModuleCount);

NTSTATUS
EnumThreadModule(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength);

#endif // !CXX_ProcessThread_H
