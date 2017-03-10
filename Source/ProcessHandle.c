#include "ProcessHandle.h"


extern DYNAMIC_DATA g_DynamicData;


/************************************************************************
*  Name : GetHandleType
*  Param: Handle				句柄	 （IN）
*  Param: wzHandleType			句柄类型 （OUT）
*  Ret  : BOOLEAN
*  ZwQueryObject+ObjectTypeInformation查询句柄类型
************************************************************************/

VOID
GetHandleType(IN HANDLE Handle, OUT PWCHAR wzHandleType)
{
	PVOID Buffer = NULL;

	Buffer = ExAllocatePool(PagedPool, PAGE_SIZE);
	if (Buffer)
	{
		UINT32   ReturnLength = 0;

		// 保存之前的模式，转成KernelMode
		PUINT8		PreviousMode = (PUINT8)PsGetCurrentThread() + g_DynamicData.PreviousMode;
		UINT8		Temp = *PreviousMode;

		RtlZeroMemory(Buffer, PAGE_SIZE);

		*PreviousMode = KernelMode;

		__try
		{
			NTSTATUS Status = ZwQueryObject(Handle, ObjectTypeInformation, Buffer, PAGE_SIZE, &ReturnLength);

			if (NT_SUCCESS(Status))
			{
				PPUBLIC_OBJECT_TYPE_INFORMATION poti = (PPUBLIC_OBJECT_TYPE_INFORMATION)Buffer;
				if (poti->TypeName.Buffer != NULL &&
					poti->TypeName.Length > 0 &&
					MmIsAddressValid(poti->TypeName.Buffer))
				{
					if (poti->TypeName.Length >= MAX_PATH - 1)
					{
						wcsncpy(wzHandleType, poti->TypeName.Buffer, (MAX_PATH - 1));
					}
					else
					{
						wcsncpy(wzHandleType, poti->TypeName.Buffer, poti->TypeName.Length);
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			;
		}

		*PreviousMode = Temp;

		ExFreePool(Buffer);
	}
}

/************************************************************************
*  Name : GetHandleName
*  Param: Handle				句柄	 （IN）
*  Param: wzHandleName			句柄名称 （OUT）
*  Ret  : BOOLEAN
*  ZwQueryObject+ObjectNameInformation查询句柄名称
************************************************************************/

VOID
GetHandleName(IN HANDLE Handle, OUT PWCHAR wzHandleName)
{
	PVOID Buffer = NULL;

	Buffer = ExAllocatePool(PagedPool, PAGE_SIZE);
	if (Buffer)
	{
		UINT32   ReturnLength = 0;

		// 保存之前的模式，转成KernelMode
		PUINT8		PreviousMode = (PUINT8)PsGetCurrentThread() + g_DynamicData.PreviousMode;
		UINT8		Temp = *PreviousMode;

		RtlZeroMemory(Buffer, PAGE_SIZE);

		*PreviousMode = KernelMode;

		__try
		{
			NTSTATUS Status = ZwQueryObject(Handle, ObjectNameInformation, Buffer, PAGE_SIZE, &ReturnLength);

			if (NT_SUCCESS(Status))
			{
				POBJECT_NAME_INFORMATION oni = (POBJECT_NAME_INFORMATION)Buffer;
				if (oni->Name.Buffer != NULL &&
					oni->Name.Length > 0 &&
					MmIsAddressValid(oni->Name.Buffer))
				{
					if (oni->Name.Length >= MAX_PATH - 1)
					{
						wcsncpy(wzHandleName, oni->Name.Buffer, (MAX_PATH - 1));
					}
					else
					{
						wcsncpy(wzHandleName, oni->Name.Buffer, oni->Name.Length);
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			;
		}

		*PreviousMode = Temp;

		ExFreePool(Buffer);
	}
}

/************************************************************************
*  Name : CopyHandleInformation
*  Param: EProcess			进程结构体				 （IN）
*  Param: Handle			进程句柄				 （IN）
*  Param: Object			进程对象				 （IN）
*  Param: phi				Ring3层进程句柄信息结构体（OUT）
*  Ret  : NTSTATUS
*  枚举目标进程的句柄信息，存入Ring3提供结构体
************************************************************************/

VOID
CopyHandleInformation(IN PEPROCESS EProcess, IN HANDLE Handle, IN PVOID Object, OUT PPROCESS_HANDLE_INFORMATION phi)
{

	PROCESS_HANDLE_ENTRY_INFORMATION  phei = { 0 };

	if (Object && MmIsAddressValid(Object))
	{
		KAPC_STATE	ApcState = { 0 };

		phei.Handle = Handle;
		phei.Object = Object;

		if (MmIsAddressValid((PUINT8)Object - g_DynamicData.SizeOfObjectHeader))
		{
			phei.ReferenceCount = *(PUINT_PTR)((PUINT8)Object - g_DynamicData.SizeOfObjectHeader);
		}
		else
		{
			phei.ReferenceCount = 0;
		}

		// 转到目标进程空间上下背景文里
		KeStackAttachProcess(EProcess, &ApcState);

		GetHandleName(Handle, phei.wzHandleName);
		GetHandleType(Handle, phei.wzHandleType);

		KeUnstackDetachProcess(&ApcState);

		RtlCopyMemory(&phi->Handles[phi->NumberOfHandles], &phei, sizeof(phei));
	}
}


/************************************************************************
*  Name : EnumProcessHandle
*  Param: ProcessId				进程Id				 （IN）
*  Param: phi					Ring3层需要的内存信息（OUT）
*  Param: OutputLength			Ring3层传递的返出长度（OUT）
*  Ret  : NTSTATUS
*  枚举目标进程的句柄信息，存入Ring3提供结构体
************************************************************************/

NTSTATUS
EnumProcessHandle(IN UINT32 ProcessId, OUT PPROCESS_HANDLE_INFORMATION phi, IN UINT32 OutputLength)
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
				UINT32	NumberOfHandles = (OutputLength - sizeof(PROCESS_HANDLE_INFORMATION)) / sizeof(PROCESS_HANDLE_ENTRY_INFORMATION);		// Ring3传递的0x1000

				UINT32   ReturnLength = PAGE_SIZE;

				// 保存之前的模式，转成KernelMode
				PUINT8		PreviousMode = (PUINT8)PsGetCurrentThread() + g_DynamicData.PreviousMode;
				UINT8		Temp = *PreviousMode;

				*PreviousMode = KernelMode;

				do
				{
					PVOID Buffer = ExAllocatePool(PagedPool, ReturnLength);
					if (Buffer != NULL)
					{
						RtlZeroMemory(Buffer, ReturnLength);

						// 扫描系统所有进程的句柄信息
						Status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, ReturnLength, &ReturnLength);
						if (NT_SUCCESS(Status))
						{
							PSYSTEM_HANDLE_INFORMATION shi = (PSYSTEM_HANDLE_INFORMATION)Buffer;

							for (INT i = 0; i < shi->NumberOfHandles; i++)
							{
								if (ProcessId == shi->Handles[i].UniqueProcessId)
								{
									if (NumberOfHandles > phi->NumberOfHandles)
									{
										CopyHandleInformation(EProcess, (HANDLE)shi->Handles[i].HandleValue, (PVOID)shi->Handles[i].Object, phi);
									}
									// 记录句柄个数
									phi->NumberOfHandles++;
								}
							}
						}
						ExFreePool(Buffer);
					}
				} while (Status == STATUS_INFO_LENGTH_MISMATCH);

				*PreviousMode = Temp;

				if (NumberOfHandles >= phi->NumberOfHandles)
				{
					Status = STATUS_SUCCESS;
				}
				else
				{
					Status = STATUS_BUFFER_TOO_SMALL;
				}
			}
		}
	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	return Status;
}

