#include "SysIoTimer.h"

typedef
//NTKERNELAPI
VOID ( * pfnIoStartTimer)(
	IN PDEVICE_OBJECT DeviceObject);

typedef
//NTKERNELAPI
VOID ( * pfnIoStopTimer)(
	IN PDEVICE_OBJECT DeviceObject);

UINT_PTR
GetIopTimerQueueHead()
{
	PUINT8		IoInitializeTimerAddress = NULL;

	GetNtosExportVariableAddress(L"IoInitializeTimer", &IoInitializeTimerAddress);
	DbgPrint("%p\r\n", IoInitializeTimerAddress);

	if (IoInitializeTimerAddress != NULL)
	{
		PUINT8	StartSearchAddress = IoInitializeTimerAddress;
		PUINT8	EndSearchAddress = StartSearchAddress + 0x200;
		PUINT8	i = NULL;
		UINT8   v1 = 0, v2 = 0, v3 = 0;
		INT32   iOffset = 0;    // 注意这里的偏移可正可负 不能定UINT型
		UINT64  VariableAddress = 0;

		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
			{
				/*
					kd> u IoInitializeTimer l 50
					nt!IoInitializeTimer:
					fffff800`042cb3b0 48895c2408      mov     qword ptr [rsp+8],rbx
					......
					fffff800`042cb420 488d0dd94ce0ff  lea     rcx,[nt!IopTimerQueueHead (fffff800`040d0100)]
				*/

				v1 = *i;
				v2 = *(i + 1);
				v3 = *(i + 2);
				if (v1 == 0x48 && v2 == 0x8d && v3 == 0x0d)		// 硬编码  lea rcx
				{
					memcpy(&iOffset, i + 3, 4);
					return iOffset + (UINT64)i + 7;
				}
			}
		}
	}
	return 0;
}


NTSTATUS
EnumIoTimer(OUT PVOID OutputBuffer, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PIO_TIMER_INFORMATION iti = (PIO_TIMER_INFORMATION)OutputBuffer;
	UINT32 NumberOfIoTimers = (OutputLength - sizeof(IO_TIMER_INFORMATION)) / sizeof(IO_TIMER_ENTRY_INFORMATION);

	PLIST_ENTRY IopTimerQueueHead = (PLIST_ENTRY)GetIopTimerQueueHead();

	KIRQL OldIrql = 0;
	OldIrql = KeRaiseIrqlToDpcLevel();

	if (IopTimerQueueHead && MmIsAddressValid((PVOID)IopTimerQueueHead))
	{
		for (PLIST_ENTRY TravelListEntry = IopTimerQueueHead->Flink;
			MmIsAddressValid(TravelListEntry) && TravelListEntry != IopTimerQueueHead;
			TravelListEntry = TravelListEntry->Flink)
		{
			/* Win7 x64
			kd> dt _IO_TIMER
			nt!_IO_TIMER
			+0x000 Type             : Int2B
			+0x002 TimerFlag        : Int2B
			+0x008 TimerList        : _LIST_ENTRY
			+0x018 TimerRoutine     : Ptr64     void
			+0x020 Context          : Ptr64 Void
			+0x028 DeviceObject     : Ptr64 _DEVICE_OBJECT
			*/

			PIO_TIMER IoTimer = CONTAINING_RECORD(TravelListEntry, IO_TIMER, TimerList);
			if (IoTimer && MmIsAddressValid(IoTimer))
			{
				UINT_PTR CurrentCount = iti->NumberOfIoTimers;
				if (NumberOfIoTimers > CurrentCount)
				{
					DbgPrint("IoTimer对象:%p\r\n", (UINT_PTR)IoTimer);
					DbgPrint("IoTimer函数入口:%p\r\n", (UINT_PTR)IoTimer->TimerRoutine);
					DbgPrint("Timer状态:%p\r\n", (UINT_PTR)IoTimer->TimerFlag);

					iti->IoTimer[CurrentCount].TimerObject = (UINT_PTR)IoTimer;
					iti->IoTimer[CurrentCount].TimerEntry = (UINT_PTR)TravelListEntry;
					iti->IoTimer[CurrentCount].DeviceObject = (UINT_PTR)IoTimer->DeviceObject;
					iti->IoTimer[CurrentCount].TimeDispatch = (UINT_PTR)IoTimer->TimerRoutine;
					iti->IoTimer[CurrentCount].Status = (UINT_PTR)IoTimer->TimerFlag;
				}
				else
				{
					return STATUS_BUFFER_TOO_SMALL;
				}
				iti->NumberOfIoTimers++;
				Status = STATUS_SUCCESS;
			}
		}
	}

	KeLowerIrql(OldIrql);

	return Status;
}



NTSTATUS
RemoveIoTimer(IN PLIST_ENTRY TimerEntry)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	// 得到IopTimerQueueHead

	PLIST_ENTRY IopTimerQueueHead = (PLIST_ENTRY)GetIopTimerQueueHead();

	KIRQL OldIrql = 0;
	OldIrql = KeRaiseIrqlToDpcLevel();

	if (IopTimerQueueHead && MmIsAddressValid((PVOID)IopTimerQueueHead))
	{
		for (PLIST_ENTRY TravelListEntry = IopTimerQueueHead->Flink;
			MmIsAddressValid(TravelListEntry) && TravelListEntry != IopTimerQueueHead;
			TravelListEntry = TravelListEntry->Flink)
		{
			if (TravelListEntry == TimerEntry)		// 找到了目标
			{
				PIO_TIMER IoTimer = CONTAINING_RECORD(TravelListEntry, IO_TIMER, TimerList);
				if (IoTimer && MmIsAddressValid(IoTimer))
				{
					RemoveEntryList(TravelListEntry);	// 断链
					ExFreePoolWithTag(IoTimer, 0);       // 释放内存
					Status = STATUS_SUCCESS;
				}
				break;
			}
		}
	}

	KeLowerIrql(OldIrql);

	return Status;
}


NTSTATUS
RunOrStopIoTimer(IN POPERATION_ON_IO_TIMER_INFORMATION OperationOnIoTimer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PDEVICE_OBJECT DeviceObject = (PDEVICE_OBJECT)OperationOnIoTimer->DeviceObject;

	if (DeviceObject && MmIsAddressValid(DeviceObject))
	{
		if (OperationOnIoTimer->bRun)
		{
			pfnIoStartTimer IoStartTimer = NULL;
			GetNtosExportVariableAddress(L"IoStartTimer", (PVOID*)&IoStartTimer);
			if (IoStartTimer)
			{
				IoStartTimer(DeviceObject);
				Status = STATUS_SUCCESS;
			}
		}
		else
		{
			pfnIoStopTimer IoStopTimer = NULL;
			GetNtosExportVariableAddress(L"IoStopTimer", (PVOID*)&IoStopTimer);
			if (IoStopTimer)
			{
				IoStopTimer(DeviceObject);
				Status = STATUS_SUCCESS;
			}
		}
	}

	return Status;
}