#ifndef CXX_ProcessPrivilage_H
#define CXX_ProcessPrivilage_H

#include <ntifs.h>

typedef struct _PRIVILEGE_DATA
{
	UINT32           ProcessId;
	TOKEN_PRIVILEGES TokenPrivileges;
} PRIVILEGE_DATA, *PPRIVILEGE_DATA;

NTSTATUS
EnumProcessPrivilege(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength);

NTSTATUS
AdjustProcessTokenPrivileges(OUT PPRIVILEGE_DATA PrivilegeData, OUT int *bFeedBack);




#endif // !CXX_ProcessPrivilage_H
