#include "ProcessThread.h"
#include "ProcessCore.h"
#include "Private.h"
#include "Imports.h"
#include "NtStructs.h"

extern UINT32  g_SelfProcessId;
extern DYNAMIC_DATA g_DynamicData;



BOOLEAN
IsThreadInList(IN PETHREAD EThread, IN PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 NumberOfThreads)
{
	BOOLEAN   bOk = FALSE;
	UINT32 i = 0;

	NumberOfThreads = NumberOfThreads > ProcessThreads->NumberOfThreads ? ProcessThreads->NumberOfThreads : NumberOfThreads;

	if (!EThread || !ProcessThreads)
	{
		return TRUE;
	}

	for (i = 0; i < NumberOfThreads; i++)
	{
		if (ProcessThreads->Threads[i].EThread == (UINT_PTR)EThread)	// 匹配的上说明已经有了
		{
			bOk = TRUE;
			break;
		}
	}

	return bOk;
}

// StartAddress域包含了线程的启动地址，这是真正的线程启动地址，即入口地址。也就是我们在创建线程的之后指定的入口函数的地址
// Win32StartAddress包含的是windows子系统接收到的线程启动地址，即CreateThread函数接收到的线程启动地址
//  StartAddress域包含的通常是系统DLL中的线程启动地址，因而往往是相同的(例如kernel32.dll中的BaseProcessStart或BaseThreadStart函数)。
// 而Win32StartAddress域中包含的才真正是windows子系统接收到的线程启动地址，即CreateThread中指定的那个函数入口地址。
UINT_PTR 
GetThreadStartAddress(IN PETHREAD EThread)
{
	UINT_PTR StartAddress = 0;

	if (!EThread ||
		!MmIsAddressValid(EThread))
	{
		return StartAddress;
	}

	__try
	{
		// 版本号大于6000
		StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.StartAddress);

		if (*(PUINT_PTR)((PUINT8)EThread + g_DynamicData.SameThreadApcFlags) & 2)	// StartAddressInvalid
		{
			StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.Win32StartAddress);	// 线程真实入口地址
		}
		else
		{
			if (*(PUINT_PTR)((PUINT8)EThread + g_DynamicData.StartAddress))
			{
				StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.StartAddress);
			}
		}

		if (StartAddress <= 0xf)
		{
			g_DynamicData.Win32StartAddress = 0x418;	//0x410 0x418
			g_DynamicData.StartAddress = 0x390;			//0x388 0x390
		}

		if (*(PUINT_PTR)((PUINT8)EThread + g_DynamicData.SameThreadApcFlags) & 2)	// StartAddressInvalid
		{
			StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.Win32StartAddress);	// 线程真实入口地址
		}
		else
		{
			if (*(PUINT_PTR)((PUINT8)EThread + g_DynamicData.StartAddress))
			{
				StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.StartAddress);
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{}

	return StartAddress;
}

// 给结构体赋值
VOID 
FillProcessThreadInfo(IN PETHREAD EThread, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 NumberOfThreads)
{
	if (EThread && EProcess && MmIsAddressValid((PVOID)EThread))
	{
		// 通过线程体获得当前进程体
		PEPROCESS CurrentEProcess = NULL;
		if (IoThreadToProcess)
		{
			CurrentEProcess = IoThreadToProcess(EThread);
		}
		else
		{
			CurrentEProcess = (PEPROCESS)*(PUINT_PTR)((PUINT8)EThread + g_DynamicData.Process);
		}

		if (EProcess == CurrentEProcess &&
			!IsThreadInList(EThread, ProcessThreads, NumberOfThreads) &&
			NT_SUCCESS(ObReferenceObjectByPointer(EThread, 0, NULL, KernelMode)))
		{
			UINT32 CurrentCount = ProcessThreads->NumberOfThreads;
			if (NumberOfThreads > CurrentCount)
			{
				if (PsGetThreadId)
				{
					ProcessThreads->Threads[CurrentCount].ThreadId = (UINT32)PsGetThreadId(EThread);
				}
				else
				{
					ProcessThreads->Threads[CurrentCount].ThreadId = (UINT32)*(PUINT_PTR)((PUINT8)EThread + g_DynamicData.Cid + sizeof(PVOID));
				}

				ProcessThreads->Threads[CurrentCount].EThread = (UINT_PTR)EThread;
				ProcessThreads->Threads[CurrentCount].Win32StartAddress = GetThreadStartAddress(EThread);
				ProcessThreads->Threads[CurrentCount].Teb = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.Teb);
				ProcessThreads->Threads[CurrentCount].Priority = *((PUINT8)EThread + g_DynamicData.Priority);
				ProcessThreads->Threads[CurrentCount].ContextSwitches = *(PUINT32)((PUINT8)EThread + g_DynamicData.ContextSwitches);
				ProcessThreads->Threads[CurrentCount].State = *((PUINT8)EThread + g_DynamicData.State);
			}
			ProcessThreads->NumberOfThreads++;

			ObDereferenceObject(EThread);
		}
	}
}

NTSTATUS
EnumProcessThread(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UINT32    NumberOfThreads = 0;
	PEPROCESS EProcess = NULL;

	NumberOfThreads = (OutputBufferLength - sizeof(PROCESS_THREAD_INFORMATION)) / sizeof(PROCESS_THREAD_ENTRY_INFORMATION);

	if (ProcessId == 0)
	{
		return Status;
	}
	else
	{
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
	}

	//////////////////////////////////////////////////////////////////////////
	/*
	进程的所有线程通过LIST_ENTRY结构链在了一个双向循环链表上。
	一个链表是以EPROCESS结构的KPROCESSPcb中的ThreadListHead为链表的链表头。链上的每一项是一个线程的KTHREADETHREAD结构的Tcb中的ThreadListEntry。
	另一个链表是以EPROCESS结构中的ThreadListHead为链表的链表头。链上的每一项是一个线程的ETHREAD结构中的ThreadListEntry。
	通过这两个链表中的任何一个，都可以找到一个进程的所有线程的ETHREAD结构，当然找到ETHREAD结构，就可以找到ETHREAD结构中的KTHREAD。
	*/

	if (NT_SUCCESS(Status) && IsValidProcess(EProcess))
	{
		PLIST_ENTRY  ListEntry = (PLIST_ENTRY)((PUINT8)EProcess + g_DynamicData.ThreadListHead_KPROCESS);
		if (ListEntry && MmIsAddressValid(ListEntry) && MmIsAddressValid(ListEntry->Flink))
		{
			KIRQL       OldIrql = KeRaiseIrqlToDpcLevel();
			UINT_PTR    MaxCount = PAGE_SIZE * 2;
			PLIST_ENTRY TravelList = ListEntry->Flink;

			while (MmIsAddressValid(TravelList) && TravelList != ListEntry && MaxCount--)
			{
				PETHREAD EThread = (PETHREAD)((PUINT8)TravelList - g_DynamicData.ThreadListEntry_KTHREAD);
				FillProcessThreadInfo(EThread, EProcess, OutputBuffer, NumberOfThreads);
				TravelList = TravelList->Flink;
			}

			KeLowerIrql(OldIrql);
		}

		ListEntry = (PLIST_ENTRY)((PUINT8)EProcess + g_DynamicData.ThreadListHead_EPROCESS);
		if (ListEntry && MmIsAddressValid(ListEntry) && MmIsAddressValid(ListEntry->Flink))
		{
			KIRQL       OldIrql = KeRaiseIrqlToDpcLevel();
			UINT_PTR    MaxCount = PAGE_SIZE * 2;
			PLIST_ENTRY TravelList = ListEntry->Flink;

			while (MmIsAddressValid(TravelList) && TravelList != ListEntry && MaxCount--)
			{
				PETHREAD EThread = (PETHREAD)((PUINT8)TravelList - g_DynamicData.ThreadListEntry_ETHREAD);
				FillProcessThreadInfo(EThread, EProcess, OutputBuffer, NumberOfThreads);
				TravelList = TravelList->Flink;
			}

			KeLowerIrql(OldIrql);
		}

		if (NumberOfThreads >= ((PPROCESS_THREAD_INFORMATION)OutputBuffer)->NumberOfThreads)
		{
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_BUFFER_TOO_SMALL;	// 内存不够
		}

	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	return Status;
}


