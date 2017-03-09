#include "ProcessThread.h"
#include "ProcessCore.h"
#include "Private.h"
#include "Imports.h"
#include "NtStructs.h"

extern UINT32  g_SelfProcessId;
extern DYNAMIC_DATA g_DynamicData;



BOOLEAN
IsThreadInList(IN PETHREAD EThread, IN PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 ThreadCount)
{
	BOOLEAN   bOk = FALSE;
	int i = 0;

	ThreadCount = ThreadCount > ProcessThreads->ThreadCount ? ProcessThreads->ThreadCount : ThreadCount;

	if (!EThread || !ProcessThreads)
	{
		return TRUE;
	}

	for (i = 0; i < ThreadCount; i++)
	{
		if (ProcessThreads->Threads[i].EThread == (UINT_PTR)EThread)	// ƥ�����˵���Ѿ�����
		{
			bOk = TRUE;
			break;
		}
	}

	return bOk;
}

// StartAddress��������̵߳�������ַ�������������߳�������ַ������ڵ�ַ��Ҳ���������ڴ����̵߳�֮��ָ������ں����ĵ�ַ
// Win32StartAddress��������windows��ϵͳ���յ����߳�������ַ����CreateThread�������յ����߳�������ַ
//  StartAddress�������ͨ����ϵͳDLL�е��߳�������ַ�������������ͬ��(����kernel32.dll�е�BaseProcessStart��BaseThreadStart����)��
// ��Win32StartAddress���а����Ĳ�������windows��ϵͳ���յ����߳�������ַ����CreateThread��ָ�����Ǹ�������ڵ�ַ��
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
		// �汾�Ŵ���6000
		StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.StartAddress);

		if (*(PUINT_PTR)((PUINT8)EThread + g_DynamicData.SameThreadApcFlags) & 2)	// StartAddressInvalid
		{
			StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.Win32StartAddress);	// �߳���ʵ��ڵ�ַ
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
			StartAddress = *(PUINT_PTR)((PUINT8)EThread + g_DynamicData.Win32StartAddress);	// �߳���ʵ��ڵ�ַ
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

// ���ṹ�帳ֵ
VOID 
FillProcessThreadInfo(IN PETHREAD EThread, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION ProcessThreads, IN UINT32 ThreadCount)
{
	if (EThread && EProcess && MmIsAddressValid((PVOID)EThread))
	{
		// ͨ���߳����õ�ǰ������
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
			!IsThreadInList(EThread, ProcessThreads, ThreadCount) &&
			NT_SUCCESS(ObReferenceObjectByPointer(EThread, 0, NULL, KernelMode)))
		{
			UINT32 CurrentCount = ProcessThreads->ThreadCount;
			if (ThreadCount > CurrentCount)
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
			ProcessThreads->ThreadCount++;

			ObDereferenceObject(EThread);
		}
	}
}


NTSTATUS
EnumProcessThread(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UINT32    ThreadCount = 0;
	PEPROCESS EProcess = NULL;


	ThreadCount = (OutputBufferLength - sizeof(PROCESS_THREAD_INFORMATION)) / sizeof(PROCESS_THREAD_ENTRY_INFORMATION);

	if (ProcessId == 0)
	{
		;
	}
/*	else if (ProcessId == g_SelfProcessId)
	{
		EProcess = PsGetCurrentProcess();
		Status = STATUS_SUCCESS;
	}*/
	else
	{
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
	}

	//////////////////////////////////////////////////////////////////////////
	/*
	���̵������߳�ͨ��LIST_ENTRY�ṹ������һ��˫��ѭ�������ϡ�
	һ����������EPROCESS�ṹ��KPROCESSPcb�е�ThreadListHeadΪ���������ͷ�����ϵ�ÿһ����һ���̵߳�KTHREADETHREAD�ṹ��Tcb�е�ThreadListEntry��
	��һ����������EPROCESS�ṹ�е�ThreadListHeadΪ���������ͷ�����ϵ�ÿһ����һ���̵߳�ETHREAD�ṹ�е�ThreadListEntry��
	ͨ�������������е��κ�һ�����������ҵ�һ�����̵������̵߳�ETHREAD�ṹ����Ȼ�ҵ�ETHREAD�ṹ���Ϳ����ҵ�ETHREAD�ṹ�е�KTHREAD��
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
				FillProcessThreadInfo(EThread, EProcess, OutputBuffer, ThreadCount);
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
				FillThreadInfo(EThread, EProcess, OutputBuffer, ThreadCount);
				TravelList = TravelList->Flink;
			}

			KeLowerIrql(OldIrql);
		}

		if (ThreadCount >= ((PPROCESS_THREAD_INFORMATION)OutputBuffer)->ThreadCount)
		{
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_BUFFER_TOO_SMALL;	// �ڴ治��
		}

	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	return Status;
}


BOOLEAN 
IsModuleInList(IN UINT_PTR BaseAddress, IN UINT32 ModuleSize, IN PTHREAD_MODULE_INFORMATION ThreadModule, IN UINT_PTR ModuleCount)
{
	BOOLEAN bOk = FALSE;
	UINT32  i = 0;
	ModuleCount = ThreadModule->ModuleCount > ModuleCount ? ModuleCount : ThreadModule->ModuleCount;

	for (i = 0; i < ModuleCount; i++)
	{
		if (BaseAddress == ThreadModule->Modules[i].BaseAddress && 
			ModuleSize == ThreadModule->Modules[i].Size)
		{
			bOk = TRUE;
			break;
		}
	}
	return bOk;
}

VOID
FillThreadModuleInfo()
{



	for (PLIST_ENTRY TravelListEntry = (PLIST_ENTRY)((PPEB_LDR_DATA)Peb->Ldr)->InLoadOrderModuleList.Flink;
		TravelListEntry != &((PPEB_LDR_DATA)Peb->Ldr)->InLoadOrderModuleList;
		TravelListEntry = (PLIST_ENTRY)TravelListEntry->Flink)
	{
		// ��ʵ�����׵�ַ
		PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(TravelListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if ((PUINT8)LdrDataTableEntry > 0)
		{
			if (!IsModuleInList(LdrDataTableEntry->DllBase, LdrDataTableEntry->SizeOfImage, ThreadModule, ModuleCount))
			{
				if (ModuleCount > ThreadModule->ModuleCount)	// Ring3���Ĵ� �ͼ�����
				{
					ThreadModule->Modules[ThreadModule->ModuleCount].BaseAddress = (UINT_PTR)LdrDataTableEntry->DllBase;
					ThreadModule->Modules[ThreadModule->ModuleCount].Size = LdrDataTableEntry->SizeOfImage;

					wcsncpy(ThreadModule->Modules[ThreadModule->ModuleCount].wzFileFullPath, LdrDataTableEntry->FullDllName.Buffer, LdrDataTableEntry->FullDllName.Length);
				}

				ThreadModule->ModuleCount++;
			}
		}
	}


}

NTSTATUS
EnumDllModuleByPeb(IN PEPROCESS EProcess, OUT PTHREAD_MODULE_INFORMATION ThreadModule, UINT32 ModuleCount)
{
	BOOLEAN bAttach = FALSE;
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	KeStackAttachProcess(EProcess, &ApcState);
	bAttach = TRUE;

	__try
	{
		LARGE_INTEGER	Interval = { 0 };
		Interval.QuadPart = -25011 * 10 * 1000;		// 250 ����

		if (TRUE)		// ��Ҫ���� Wow64������
		{

			PPEB Peb = PsGetProcessPeb(EProcess);
			if (Peb == NULL)
			{
				return Status;
			}

			for (INT i = 0; Peb->Ldr == 0 && i < 10; i++)
			{
				// Sleep �ȴ�����
				KeDelayExecutionThread(KernelMode, TRUE, &Interval);
			}

			if (Peb->Ldr == 0)
			{
				// ��Ȼû�м�����
				return NULL;
			}

			FillThreadModuleInfo();
			
			Status = STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("EnumDllModuleByPeb Catch __Except\r\n");
		Status = STATUS_UNSUCCESSFUL;
	}

	if (bAttach)
	{
		KeUnstackDetachProcess(&ApcState);
		bAttach = FALSE;
	}

	return Status;
}



NTSTATUS
EnumThreadModule(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess = NULL;

	ULONG ModuleCount = (OutputBufferLength - sizeof(THREAD_MODULE_INFORMATION)) / sizeof(THREAD_MODULE_ENTRY_INFORMATION);

	if (ProcessId == 0)
	{
		;
	}
	else
	{
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
	}

	if (NT_SUCCESS(Status) && IsValidProcess(EProcess))
	{
		PTHREAD_MODULE_INFORMATION ThreadModule = (PTHREAD_MODULE_INFORMATION)ExAllocatePool(PagedPool, OutputBufferLength);
		if (ThreadModule)
		{
			RtlZeroMemory(ThreadModule, OutputBufferLength);

			Status = EnumDllModuleByPeb(EProcess, ThreadModule, ModuleCount);

			if (ModuleCount >= ThreadModule->ModuleCount)
			{
				RtlCopyMemory(OutputBuffer, ThreadModule, OutputBufferLength);
				Status = STATUS_SUCCESS;
			}
			else
			{
				Status = STATUS_BUFFER_TOO_SMALL;
			}

			ExFreePool(ThreadModule, 0);
			ThreadModule = NULL;
		}
	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	return Status;
}