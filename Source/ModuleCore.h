#ifndef CXX_ModuleCore_H
#define CXX_ModuleCore_H

#include <ntifs.h>

#include "Private.h"
#include "ProcessCore.h"
#include "Imports.h"

typedef struct _KERNEL_MODULE_ENTRY_INFORMATION
{
	UINT_PTR LoadOrder;		// ldr
	UINT_PTR BaseAddress;   // ldr
	UINT_PTR Size;          // ldr
	UINT_PTR DriverObject;  // DirectoryObject
	UINT_PTR DirverStartAddress;// DirectoryObject
	WCHAR    wzDriverPath[MAX_PATH]; // ldr
	WCHAR    wzKeyName[MAX_PATH];    // DirectoryObject
} KERNEL_MODULE_ENTRY_INFORMATION, *PKERNEL_MODULE_ENTRY_INFORMATION;

typedef struct _KERNEL_MODULE_INFORMATION
{
	UINT_PTR                        NumberOfDrivers;
	KERNEL_MODULE_ENTRY_INFORMATION Drivers[1];
} KERNEL_MODULE_INFORMATION, *PKERNEL_MODULE_INFORMATION;

/*
NTSTATUS
NTAPI
MyZwOpenDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes);
	*/

PLDR_DATA_TABLE_ENTRY
GetKernelLdrDataTableEntry(IN PDRIVER_OBJECT DriverObject);

VOID
EnumKernelModuleByLdrDataTableEntry(IN PLDR_DATA_TABLE_ENTRY KernelLdrEntry, OUT PKERNEL_MODULE_INFORMATION kmi, IN UINT32 NumberOfDrivers);

BOOLEAN
IsDriverInList(IN PKERNEL_MODULE_INFORMATION kmi, IN PDRIVER_OBJECT DriverObject, IN UINT32 NumberOfDrivers);

VOID
InsertDriver(OUT PKERNEL_MODULE_INFORMATION kmi, IN PDRIVER_OBJECT DriverObject, IN UINT32 NumberOfDrivers);

VOID
TravelDirectoryObject(IN PVOID DirectoryObject, OUT PKERNEL_MODULE_INFORMATION kmi, IN UINT32 NumberOfDrivers);

VOID
EnumKernelModuleByDirectoryObject(OUT PKERNEL_MODULE_INFORMATION kmi, IN UINT32 NumberOfDrivers);

NTSTATUS
EnumSystemModuleList(OUT PVOID OutputBuffer, IN UINT32 OutputLength);

#endif // !CXX_ModuleCore_H
