#ifndef CXX_ProcessMemory_H
#define CXX_ProcessMemory_H

#include <ntifs.h>
#include "Private.h"
#include "NtStructs.h"
#include "ProcessCore.h"

typedef struct _PROCESS_MEMORY_ENTRY_INFORMATION
{
	UINT_PTR	BaseAddress;
	UINT_PTR	RegionSize;
	UINT32		Protect;
	UINT32		State;
	UINT32		Type;
} PROCESS_MEMORY_ENTRY_INFORMATION, *PPROCESS_MEMORY_ENTRY_INFORMATION;

typedef struct _PROCESS_MEMORY_INFORMATION
{
	UINT32								NumberOfMemories;
	PROCESS_MEMORY_ENTRY_INFORMATION	Memories[1];
} PROCESS_MEMORY_INFORMATION, *PPROCESS_MEMORY_INFORMATION;


NTSTATUS
EnumProcessMemory(IN UINT32 ProcessId, OUT PPROCESS_MEMORY_INFORMATION pmi, OUT UINT_PTR OutputLength);

#endif // !CXX_ProcessMemory_H
