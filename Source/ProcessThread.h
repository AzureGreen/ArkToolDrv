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
	UINT32                           NumberOfThreads;
	PROCESS_THREAD_ENTRY_INFORMATION Threads[1];
} PROCESS_THREAD_INFORMATION, *PPROCESS_THREAD_INFORMATION;


BOOLEAN
IsThreadInList(IN PETHREAD EThread, IN PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 NumberOfThreads);

UINT_PTR
GetThreadStartAddress(IN PETHREAD EThread);

VOID
FillProcessThreadInfo(IN PETHREAD EThread, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 NumberOfThreads);

NTSTATUS
EnumProcessThread(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength);



#endif // !CXX_ProcessThread_H
