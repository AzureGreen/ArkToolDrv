#ifndef CXX_SysCallback_H
#define CXX_SysCallback_H

#include <ntifs.h>

#include "Private.h"
#include "ProcessCore.h"



typedef enum _CALLBACK_TYPE
{
	NotifyCreateProcess,
	NotifyCreateThread,
	NotifyLoadImage,
	NotifyShutdown,
	NotifyCmpCallBack,
	NotifyKeBugCheckReason,
	NotifyKeBugCheck
} CALLBACK_TYPE;

typedef struct _SYS_CALLBACK_ENTRY_INFORMATION
{
	CALLBACK_TYPE Type;
	UINT_PTR      CallbackAddress;
	UINT_PTR      Description;
} SYS_CALLBACK_ENTRY_INFORMATION, *PSYS_CALLBACK_ENTRY_INFORMATION;

typedef struct _SYS_CALLBACK_INFORMATION
{
	UINT_PTR                       NumberOfCallbacks;
	SYS_CALLBACK_ENTRY_INFORMATION Callbacks[1];
} SYS_CALLBACK_INFORMATION, *PSYS_CALLBACK_INFORMATION;

typedef struct _CM_NOTIFY_ENTRY
{
	LIST_ENTRY		ListEntryHead;
	ULONG			UnKnown1;
	ULONG			UnKnown2;
	LARGE_INTEGER	Cookie;
	ULONG64			Context;
	ULONG64			Function;
} CM_NOTIFY_ENTRY, *PCM_NOTIFY_ENTRY;


UINT_PTR
GetPspLoadImageNotifyRoutineAddress();

BOOLEAN
GetLoadImageCallbackNotify(OUT PSYS_CALLBACK_INFORMATION sci, IN UINT32 NumberOfCallbacks);

UINT_PTR
GetPspCreateThreadNotifyRoutineAddress();

BOOLEAN
GetCreateThreadCallbackNotify(OUT PSYS_CALLBACK_INFORMATION sci, IN UINT32 NumberOfCallbacks);

UINT_PTR
GetCallbackListHeadAddress();

BOOLEAN
GetRegisterCallbackNotify(OUT PSYS_CALLBACK_INFORMATION sci, IN UINT32 NumberOfCallbacks);

UINT_PTR
GetKeBugCheckCallbackListHeadAddress();

BOOLEAN
GetBugCheckCallbackNotify(OUT PSYS_CALLBACK_INFORMATION sci, IN UINT32 NumberOfCallbacks);

UINT_PTR
GetKeBugCheckReasonCallbackListHeadAddress();

BOOLEAN
GetBugCheckReasonCallbackNotify(OUT PSYS_CALLBACK_INFORMATION sci, IN UINT32 NumberOfCallbacks);

UINT_PTR
GetIopNotifyShutdownQueueHeadAddress();

UINT_PTR
GetShutdownDispatch(IN PDEVICE_OBJECT DeviceObject);

BOOLEAN
GetShutDownCallbackNotify(OUT PSYS_CALLBACK_INFORMATION sci, IN UINT32 NumberOfCallbacks);

NTSTATUS
EnumSysCallbackNotify(OUT PVOID OutputBuffer, IN UINT32 OutputLength);

NTSTATUS
RemoveCallbackNotify(IN PSYS_CALLBACK_ENTRY_INFORMATION CallbackEntry);

#endif // !CXX_SysCallback_H
