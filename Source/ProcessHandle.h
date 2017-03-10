#ifndef CXX_ProcessHandle_H
#define CXX_ProcessHandle_H

#include <ntifs.h>
#include "Imports.h"
#include "NtStructs.h"
#include "Private.h"
#include "ProcessCore.h"

typedef struct _PROCESS_HANDLE_ENTRY_INFORMATION
{
	HANDLE		Handle;
	PVOID		Object;
	UINT32		ReferenceCount;		// 引用计数
	WCHAR		wzHandleType[MAX_PATH];
	WCHAR		wzHandleName[MAX_PATH];
} PROCESS_HANDLE_ENTRY_INFORMATION, *PPROCESS_HANDLE_ENTRY_INFORMATION;

typedef struct _PROCESS_HANDLE_INFORMATION
{
	UINT32								NumberOfHandles;
	PROCESS_HANDLE_ENTRY_INFORMATION	Handles[1];
} PROCESS_HANDLE_INFORMATION, *PPROCESS_HANDLE_INFORMATION;

VOID
GetHandleType(IN HANDLE Handle, OUT PWCHAR wzHandleType);

VOID
GetHandleName(IN HANDLE Handle, OUT PWCHAR wzHandleName);

VOID
CopyHandleInformation(IN PEPROCESS EProcess, IN HANDLE Handle, IN PVOID Object, OUT PPROCESS_HANDLE_INFORMATION phi);

NTSTATUS
EnumProcessHandle(IN UINT32 ProcessId, OUT PPROCESS_HANDLE_INFORMATION phi, IN UINT32 OutputLength);

#endif // !CXX_ProcessHandle_H
