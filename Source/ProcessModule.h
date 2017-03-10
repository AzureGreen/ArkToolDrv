#ifndef CXX_ProcessModule_H
#define CXX_ProcessModule_H

#include <ntifs.h>
#include "Private.h"
#include "Imports.h"
#include "NtStructs.h"
#include "ProcessCore.h"

typedef enum _eLdrType
{
	lt_InLoadOrderModuleList = 0,
	lt_InMemoryOrderModuleList,
	lt_InInitializationOrderModuleList
} eLdrType;

typedef struct _PROCESS_MODULE_ENTRY_INFORMATION
{
	UINT_PTR	BaseAddress;
	UINT_PTR	SizeOfImage;
	WCHAR	    wzFullPath[MAX_PATH];
} PROCESS_MODULE_ENTRY_INFORMATION, *PPROCESS_MODULE_ENTRY_INFORMATION;

typedef struct _PROCESS_MODULE_INFORMATION
{
	UINT_PTR                         NumberOfModules;
	PROCESS_MODULE_ENTRY_INFORMATION Modules[1];
} PROCESS_MODULE_INFORMATION, *PPROCESS_MODULE_INFORMATION;

BOOLEAN
IsModuleInList(IN UINT_PTR BaseAddress, IN UINT32 ModuleSize, IN PPROCESS_MODULE_INFORMATION pmi, IN UINT32 ModuleCount);

VOID
FillProcessModuleInfo(IN PLIST_ENTRY LdrListEntry, IN eLdrType LdrType, OUT PPROCESS_MODULE_INFORMATION pmi, IN UINT32 ModuleCount);

NTSTATUS
EnumDllModuleByPeb(IN PEPROCESS EProcess, OUT PPROCESS_MODULE_INFORMATION pmi, IN UINT32 ModuleCount);

NTSTATUS
EnumProcessModule(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputLength);


#endif // !CXX_ProcessModule_H
