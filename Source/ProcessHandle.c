#include "ProcessHandle.h"


extern DYNAMIC_DATA g_DynamicData;


/************************************************************************
*  Name : GetHandleType
*  Param: Handle				���	 ��IN��
*  Param: wzHandleType			������� ��OUT��
*  Ret  : BOOLEAN
*  ZwQueryObject+ObjectTypeInformation��ѯ�������
************************************************************************/

VOID
GetHandleType(IN HANDLE Handle, OUT PWCHAR wzHandleType)
{
	PVOID Buffer = NULL;

	Buffer = ExAllocatePool(PagedPool, PAGE_SIZE);
	if (Buffer)
	{
		UINT32   ReturnLength = 0;

		// ����֮ǰ��ģʽ��ת��KernelMode
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
*  Param: Handle				���	 ��IN��
*  Param: wzHandleName			������� ��OUT��
*  Ret  : BOOLEAN
*  ZwQueryObject+ObjectNameInformation��ѯ�������
************************************************************************/

VOID
GetHandleName(IN HANDLE Handle, OUT PWCHAR wzHandleName)
{
	PVOID Buffer = NULL;

	Buffer = ExAllocatePool(PagedPool, PAGE_SIZE);
	if (Buffer)
	{
		UINT32   ReturnLength = 0;

		// ����֮ǰ��ģʽ��ת��KernelMode
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
*  Param: EProcess			���̽ṹ��				 ��IN��
*  Param: Handle			���̾��				 ��IN��
*  Param: Object			���̶���				 ��IN��
*  Param: phi				Ring3����̾����Ϣ�ṹ�壨OUT��
*  Ret  : NTSTATUS
*  ö��Ŀ����̵ľ����Ϣ������Ring3�ṩ�ṹ��
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

		// ת��Ŀ����̿ռ����±�������
		KeStackAttachProcess(EProcess, &ApcState);

		GetHandleName(Handle, phei.wzHandleName);
		GetHandleType(Handle, phei.wzHandleType);

		KeUnstackDetachProcess(&ApcState);

		RtlCopyMemory(&phi->Handles[phi->NumberOfHandles], &phei, sizeof(phei));
	}
}


/************************************************************************
*  Name : EnumProcessHandle
*  Param: ProcessId				����Id				 ��IN��
*  Param: phi					Ring3����Ҫ���ڴ���Ϣ��OUT��
*  Param: OutputLength			Ring3�㴫�ݵķ������ȣ�OUT��
*  Ret  : NTSTATUS
*  ö��Ŀ����̵ľ����Ϣ������Ring3�ṩ�ṹ��
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
				UINT32	NumberOfHandles = (OutputLength - sizeof(PROCESS_HANDLE_INFORMATION)) / sizeof(PROCESS_HANDLE_ENTRY_INFORMATION);		// Ring3���ݵ�0x1000

				UINT32   ReturnLength = PAGE_SIZE;

				// ����֮ǰ��ģʽ��ת��KernelMode
				PUINT8		PreviousMode = (PUINT8)PsGetCurrentThread() + g_DynamicData.PreviousMode;
				UINT8		Temp = *PreviousMode;

				*PreviousMode = KernelMode;

				do
				{
					PVOID Buffer = ExAllocatePool(PagedPool, ReturnLength);
					if (Buffer != NULL)
					{
						RtlZeroMemory(Buffer, ReturnLength);

						// ɨ��ϵͳ���н��̵ľ����Ϣ
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
									// ��¼�������
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

