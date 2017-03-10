#ifndef CXX_Imports_H
#define CXX_Imports_H

#include <ntifs.h>
#include "NtStructs.h"

//////////////////////////////////////////////////////////////////////////
// Undocument Import

NTKERNELAPI
PPEB
PsGetProcessPeb(
	__in PEPROCESS Process
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN UINT32 SystemInformationLength,
	OUT PUINT32 ReturnLength OPTIONAL);

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID Base);

#endif // !CXX_Imports_H
