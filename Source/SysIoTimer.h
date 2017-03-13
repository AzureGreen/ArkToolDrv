#ifndef CXX_SysIoTimer_H
#define CXX_SysIoTimer_H

#include <ntifs.h>

#include "Private.h"
#include "NtStructs.h"

typedef struct _IO_TIMER_ENTRY_INFORMATION
{
	UINT_PTR TimerObject;
	UINT_PTR DeviceObject;
	UINT_PTR TimeDispatch;
	UINT_PTR TimerEntry;
	UINT32   Status;
} IO_TIMER_ENTRY_INFORMATION, *PIO_TIMER_ENTRY_INFORMATION;

typedef struct _IO_TIMER_INFORMATION
{
	UINT_PTR                   NumberOfIoTimers;
	IO_TIMER_ENTRY_INFORMATION IoTimer[1];
} IO_TIMER_INFORMATION, *PIO_TIMER_INFORMATION;

typedef struct _OPERATION_ON_IO_TIMER_INFORMATION
{
	UINT_PTR     DeviceObject;
	BOOLEAN      bRun;
} OPERATION_ON_IO_TIMER_INFORMATION, *POPERATION_ON_IO_TIMER_INFORMATION;

UINT_PTR
GetIopTimerQueueHead();

NTSTATUS
EnumIoTimer(OUT PVOID OutputBuffer, IN UINT32 OutputLength);

NTSTATUS
RemoveIoTimer(IN PLIST_ENTRY TimerEntry);

NTSTATUS
RunOrStopIoTimer(IN POPERATION_ON_IO_TIMER_INFORMATION OperationOnIoTimer);

#endif // !CXX_SysIoTimer_H
