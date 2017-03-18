#include "ProcessMemory.h"




extern DYNAMIC_DATA g_DynamicData;



/************************************************************************
*  Name : EnumProcessMemory
*  Param: ProcessId				����Id				 ��IN��
*  Param: pmi					Ring3����Ҫ���ڴ���Ϣ��OUT��
*  Param: OutputLength			Ring3�㴫�ݵķ������ȣ�OUT��
*  Ret  : NTSTATUS
*  ö��Ŀ����̵��ڴ���Ϣ������Ring3�ṩ�ṹ��
************************************************************************/

NTSTATUS
EnumProcessMemory(IN UINT32 ProcessId, OUT PPROCESS_MEMORY_INFORMATION pmi, OUT UINT_PTR OutputLength)
{
	NTSTATUS	Status = STATUS_SUCCESS;
	PEPROCESS	EProcess = NULL;

	if (ProcessId)
	{
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
		if (NT_SUCCESS(Status))
		{
			if (IsValidProcess(EProcess) == TRUE)
			{
				UINT32	NumberOfMemories = (OutputLength - sizeof(PROCESS_MEMORY_INFORMATION)) / sizeof(PROCESS_MEMORY_ENTRY_INFORMATION);		// Ring3���ݵ�0x1000

				HANDLE  ProcessHandle = NULL;

				// Ring0�򿪽��̾��
				Status = ObOpenObjectByPointer(EProcess,
					OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
					NULL,
					GENERIC_ALL,
					*PsProcessType,
					KernelMode,
					&ProcessHandle);

				if (NT_SUCCESS(Status))
				{
					UINT_PTR BaseAddress = 0;

					// ���������û����ڴ�ռ�
					while (BaseAddress < g_DynamicData.UserEndAddress)
					{
						MEMORY_BASIC_INFORMATION  mbi = { 0 };
						SIZE_T					  ReturnLength = 0;

						Status = ZwQueryVirtualMemory(ProcessHandle, (PVOID)BaseAddress, MemoryBasicInformation,
							&mbi, sizeof(MEMORY_BASIC_INFORMATION), &ReturnLength);

						if (NT_SUCCESS(Status))
						{
							if (NumberOfMemories > pmi->NumberOfMemories)
							{
								pmi->Memories[pmi->NumberOfMemories].BaseAddress = BaseAddress;
								pmi->Memories[pmi->NumberOfMemories].RegionSize = mbi.RegionSize;
								pmi->Memories[pmi->NumberOfMemories].Protect = mbi.Protect;
								pmi->Memories[pmi->NumberOfMemories].State = mbi.State;
								pmi->Memories[pmi->NumberOfMemories].Type = mbi.Type;
							}
							else
							{
								Status = STATUS_BUFFER_TOO_SMALL;
								break;
							}

							pmi->NumberOfMemories++;
							BaseAddress += mbi.RegionSize;
						}
						else
						{
							BaseAddress += PAGE_SIZE;
						}
					}
				}

				NtClose(ProcessHandle);
			}
		}
	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	return Status;
}
