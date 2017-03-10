#include "ProcessModule.h"


BOOLEAN
IsModuleInList(IN UINT_PTR BaseAddress, IN UINT32 ModuleSize, IN PPROCESS_MODULE_INFORMATION pmi, IN UINT32 ModuleCount)
{
	BOOLEAN bOk = FALSE;
	UINT32  i = 0;
	ModuleCount = pmi->NumberOfModules > ModuleCount ? ModuleCount : pmi->NumberOfModules;

	for (i = 0; i < ModuleCount; i++)
	{
		if (BaseAddress == pmi->Modules[i].BaseAddress &&
			ModuleSize == pmi->Modules[i].SizeOfImage)
		{
			bOk = TRUE;
			break;
		}
	}
	return bOk;
}

VOID
FillProcessModuleInfo(IN PLIST_ENTRY LdrListEntry, IN eLdrType LdrType, OUT PPROCESS_MODULE_INFORMATION pmi, IN UINT32 ModuleCount)
{

	for (PLIST_ENTRY TravelListEntry = LdrListEntry->Flink;
		TravelListEntry != LdrListEntry;
		TravelListEntry = (PLIST_ENTRY)TravelListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;
		switch (LdrType)
		{
		case lt_InLoadOrderModuleList:
		{
			LdrDataTableEntry = CONTAINING_RECORD(TravelListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			break;
		}
		case lt_InMemoryOrderModuleList:
		{
			LdrDataTableEntry = CONTAINING_RECORD(TravelListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			break;
		}
		case lt_InInitializationOrderModuleList:
		{
			LdrDataTableEntry = CONTAINING_RECORD(TravelListEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
			break;
		}
		default:
			break;
		}

		if ((PUINT8)LdrDataTableEntry > 0)
		{
			if (!IsModuleInList((UINT_PTR)LdrDataTableEntry->DllBase, LdrDataTableEntry->SizeOfImage, pmi, ModuleCount))
			{
				if (ModuleCount > pmi->NumberOfModules)	// Ring3给的大 就继续插
				{
					pmi->Modules[pmi->NumberOfModules].BaseAddress = (UINT_PTR)LdrDataTableEntry->DllBase;
					pmi->Modules[pmi->NumberOfModules].SizeOfImage = LdrDataTableEntry->SizeOfImage;

					wcsncpy(pmi->Modules[pmi->NumberOfModules].wzFullPath, LdrDataTableEntry->FullDllName.Buffer, LdrDataTableEntry->FullDllName.Length);
				}
				pmi->NumberOfModules++;
			}
		}
	}
}

NTSTATUS
EnumDllModuleByPeb(IN PEPROCESS EProcess, OUT PPROCESS_MODULE_INFORMATION pmi, IN UINT32 ModuleCount)
{
	BOOLEAN bAttach = FALSE;
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	KeStackAttachProcess(EProcess, &ApcState);
	bAttach = TRUE;

	__try
	{
		LARGE_INTEGER	Interval = { 0 };
		Interval.QuadPart = -25011 * 10 * 1000;		// 250 毫秒

		if (TRUE)		// 还要处理 Wow64的问题
		{
			PPEB_LDR_DATA LdrData = NULL;
			PPEB Peb = PsGetProcessPeb(EProcess);
			if (Peb == NULL)
			{
				return Status;
			}

			for (INT i = 0; Peb->Ldr == 0 && i < 10; i++)
			{
				// Sleep 等待加载
				KeDelayExecutionThread(KernelMode, TRUE, &Interval);
			}

			LdrData = Peb->Ldr;
			if ((PUINT8)LdrData > 0)
			{
				FillProcessModuleInfo((PLIST_ENTRY)&(LdrData->InLoadOrderModuleList), lt_InLoadOrderModuleList, pmi, ModuleCount);
				FillProcessModuleInfo((PLIST_ENTRY)&(LdrData->InMemoryOrderModuleList), lt_InMemoryOrderModuleList, pmi, ModuleCount);
				FillProcessModuleInfo((PLIST_ENTRY)&(LdrData->InInitializationOrderModuleList), lt_InInitializationOrderModuleList, pmi, ModuleCount);
				Status = STATUS_SUCCESS;
			}
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
EnumProcessModule(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UINT32 ModuleCount = (OutputLength - sizeof(PROCESS_MODULE_INFORMATION)) / sizeof(PROCESS_MODULE_ENTRY_INFORMATION);
	PEPROCESS EProcess = NULL;

	if (ProcessId == 0)
	{
		return Status;
	}
	else
	{
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
	}

	if (NT_SUCCESS(Status) && IsValidProcess(EProcess))
	{
		PPROCESS_MODULE_INFORMATION pmi = (PPROCESS_MODULE_INFORMATION)ExAllocatePool(PagedPool, OutputLength);
		if (pmi)
		{
			RtlZeroMemory(pmi, OutputLength);

			Status = EnumDllModuleByPeb(EProcess, pmi, ModuleCount);
			if (NT_SUCCESS(Status))
			{
				if (ModuleCount >= pmi->NumberOfModules)
				{
					RtlCopyMemory(OutputBuffer, pmi, OutputLength);
					Status = STATUS_SUCCESS;
				}
				else
				{
					Status = STATUS_BUFFER_TOO_SMALL;	// 给ring3返回内存不够的信息
				}
			}

			ExFreePool(pmi);
			pmi = NULL;
		}
	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	return Status;
}