#ifndef CXX_SysDpcTimer_H
#define CXX_SysDpcTimer_H

#include <ntifs.h>

#include "Private.h"
#include "NtStructs.h"

typedef struct _DPC_TIMER_ENTRY_INFORMATION
{
	UINT_PTR TimerObject;
	UINT_PTR RealDpc;
	UINT_PTR Cycle;       // ÖÜÆÚ
	UINT_PTR TimeDispatch;
} DPC_TIMER_ENTRY_INFORMATION, *PDPC_TIMER_ENTRY_INFORMATION;

typedef struct _DPC_TIMER_INFORMATION
{
	UINT32                      NumberOfDpcTimers;
	DPC_TIMER_ENTRY_INFORMATION DpcTimer[1];
} DPC_TIMER_INFORMATION, *PDPC_TIMER_INFORMATION;


BOOLEAN
FindKiWaitVariableAddress(OUT PUINT_PTR* KiWaitNeverAddress, OUT PUINT_PTR* KiWaitAlwaysAddress);

PKDPC
TransTimerDPCEx(IN PKTIMER Timer, IN UINT64 KiWaitNeverAddress, IN UINT64 KiWaitAlwaysAddress);

NTSTATUS
EnumDpcTimer(OUT PVOID OutputBuffer, IN UINT32 OutputLength);

NTSTATUS
RemoveDpcTimer(IN UINT_PTR TimerObject);

#endif // !CXX_SysIoTimer_H
