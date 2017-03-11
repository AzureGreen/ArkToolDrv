#ifndef CXX_Private_H
#define CXX_Private_H

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "NtStructs.h"
#include "Imports.h"

#define MAX_PATH 260
#define SEC_IMAGE  0x01000000

typedef enum _eWinVersion {
	WINVER_XP = 0x0510,
	WINVER_XP_SP1 = 0x0511,
	WINVER_XP_SP2 = 0x0512,
	WINVER_XP_SP3 = 0x0513,
	WINVER_7 = 0x0610,
	WINVER_7_SP1 = 0x0611,
	WINVER_8 = 0x0620,
	WINVER_81 = 0x0630,
	WINVER_10 = 0x0A00,
} eWinVersion;

typedef struct _DYNAMIC_DATA
{
	eWinVersion	WinVersion;					// ϵͳ�汾

	//////////////////////////////////////////////////////////////////////////
	// Process

	UINT32      ThreadListHead_KPROCESS;    // KPROCESS::ThreadListHead

	UINT32		ObjectTable;				// EPROCESS::ObjectTable

	UINT32		SectionObject;				// EPROCESS::SectionObject

	UINT32		InheritedFromUniqueProcessId;// EPROCESS::InheritedFromUniqueProcessId

	UINT32      ThreadListHead_EPROCESS;      // EPROCESS::ThreadListHead

	//////////////////////////////////////////////////////////////////////////
	// Thread

	UINT32      Priority;                   // KTHREAD::Priority

	UINT32      Teb;                        // KTHREAD::Teb

	UINT32      ContextSwitches;            // KTHREAD::ContextSwitches

	UINT32      State;                      // KTHREAD::State

	UINT32		PreviousMode;				// KTHREAD::PreviousMode

	UINT32      Process;                    // KTHREAD::Process	

	UINT32      ThreadListEntry_KTHREAD;    // KTHREAD::ThreadListEntry

	UINT32      StartAddress;               // ETHREAD::StartAddress

	UINT32      Cid;                        // ETHREAD::Cid

	UINT32      Win32StartAddress;          // ETHREAD::Win32StartAddress

	UINT32      ThreadListEntry_ETHREAD;    // ETHREAD::ThreadListEntry

	UINT32      SameThreadApcFlags;         // ETHREAD::SameThreadApcFlags

	//////////////////////////////////////////////////////////////////////////

	UINT32		SizeOfObjectHeader;			// Size of ObjectHeader;

	//////////////////////////////////////////////////////////////////////////

	
	UINT_PTR	UserEndAddress;				// Max Address Of Ring3 Can Visit

	UINT32		NtQueryVirtualMemoryIndex;	// NtQueryVirtualMemory Index In SSDT

	//////////////////////////////////////////////////////////////////////////

	UINT_PTR    KernelStartAddress;			// Start Address Of System

	UINT32      NtOpenDirectoryObjectIndex; // NtOpenDirectoryObject Index In SSDT

	UINT32		NtProtectVirtualMemoryIndex; // NtProtectVirtualMemory Index In SSDT

	UINT32		NtReadVirtualMemoryIndex;	// NtReadVirtualMemory Index In SSDT

	UINT32		NtWriteVirtualMemoryIndex;	// NtWriteVirtualMemory Index In SSDT

	

} DYNAMIC_DATA, *PDYNAMIC_DATA;

/*
NTSTATUS
NTAPI
MyZwOpenDirectoryObject(
__out PHANDLE DirectoryHandle,
__in ACCESS_MASK DesiredAccess,
__in POBJECT_ATTRIBUTES ObjectAttributes);
*/


NTSTATUS
ZwQueryVirtualMemory(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation, 
	IN SIZE_T MemoryInformationLength, 
	OUT PSIZE_T ReturnLength);


UINT8
ChangeThreadMode(IN PETHREAD EThread, IN UINT8 WantedMode);

NTSTATUS
SearchPattern(IN PUINT8 Pattern, IN UINT8 MatchWord, IN UINT_PTR PatternLength, IN const PVOID BaseAddress, IN UINT_PTR BaseSize, OUT PVOID * FoundAddress);

BOOLEAN
GetSSDTAddress(OUT PSYSTEM_SERVICE_DESCRIPTOR_TABLE* SSDTAddress);

BOOLEAN
GetKernelBase(OUT PVOID * KernelBase, OUT PUINT32 KernelSize);

PVOID
GetSSDTEntry(IN UINT32 FunctionIndex);

BOOLEAN
MappingPEFileInKernelSpace(IN WCHAR* wzFileFullPath, OUT PVOID* MappingBaseAddress, OUT PSIZE_T MappingViewSize);

BOOLEAN
GetSSDTFunctionIndex(IN CHAR* szTargetFunctionName, OUT PUINT32 SSDTFunctionIndex);

BOOLEAN
IsUnicodeStringValid(IN PUNICODE_STRING uniString);

#endif // !CXX_Private_H
