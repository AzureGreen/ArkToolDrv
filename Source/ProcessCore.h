#ifndef CXX_ProcessCore_H
#define CXX_ProcessCore_H

#include <ntifs.h>
#include "Private.h"
#include "NtStructs.h"

#define MAX_PROCESS_COUNT  100000

typedef struct _PROCESS_INFORMATION
{
	WCHAR     wzImageName[100];
	WCHAR     wzFileFullPath[260];
	WCHAR     wzCompanyName[100];
	INT32     bUserAccess;
	UINT32	  ProcessId;
	UINT32	  ParentProcessId;
	UINT_PTR  Eprocess;
	UINT64    CreateTime;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION;

UINT8
ChangeThreadMode(IN PETHREAD EThread, IN UINT8 WantedMode);

BOOLEAN 
IsValidProcess(IN PEPROCESS EProcess);

BOOLEAN 
IsActiveProcess(IN PEPROCESS EProcess);

UINT_PTR 
KeGetObjectType(IN PVOID Object);

BOOLEAN 
GetNtosExportVariableAddress(IN WCHAR * wzVariableName, OUT PVOID * VariableAddress);

PEPROCESS
GetIdleEProcess();

UINT_PTR
GetParentProcessIdByEProcess(IN PEPROCESS EProcess);

NTSTATUS
SetSelfProcessId(IN UINT32 ProcessId, OUT PVOID OutputBuffer, OUT PUINT32 OutputBufferLength);

NTSTATUS
GetSystemProcessCount(OUT PVOID OutputBuffer, OUT PUINT32 OutputBufferLength);

NTSTATUS
EnumSystemProcessList(IN UINT32 BaseProcessId, OUT PVOID OutputBuffer, OUT PUINT32 OutputBufferLength);

NTSTATUS
KillProcess(IN UINT32 ProcessId, OUT PINT32 OutputBuffer);

#endif // !CXX_ProcessCore_H
