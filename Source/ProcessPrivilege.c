#include "ProcessPrivilege.h"

#include "ProcessCore.h"

extern DYNAMIC_DATA g_DynamicData;

NTSTATUS
EnumProcessPrivilege(IN UINT32 ProcessId, OUT PVOID OutputBuffer, IN UINT32 OutputBufferLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PEPROCESS EProcess = NULL;

	if (ProcessId == 0)
	{
		return Status;
	}

	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
	if (NT_SUCCESS(Status) && IsValidProcess(EProcess))
	{
		// 通过进程体结构获得进程句柄
		
		HANDLE ProcessHandle = NULL;

		Status = ObOpenObjectByPointer(EProcess,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			GENERIC_ALL,
			*PsProcessType,
			KernelMode,
			&ProcessHandle);
		if (NT_SUCCESS(Status))
		{
		//	PETHREAD EThread = NULL;
		//	UINT8    PreviousMode = 0;
			HANDLE   TokenHandle = NULL;

			// 保存之前的模式，转成KernelMode
			PUINT8   PreviousMode = (PUINT8)PsGetCurrentThread() + g_DynamicData.PreviousMode;
			UINT8    Temp = *PreviousMode;

			*PreviousMode = KernelMode;

	//		EThread = PsGetCurrentThread();
	//		PreviousMode = ChangeThreadMode(EThread, KernelMode);

			Status = NtOpenProcessToken(ProcessHandle, SACL_SECURITY_INFORMATION, &TokenHandle);
			if (NT_SUCCESS(Status))
			{
				ULONG ReturnLength = 0;

				Status = NtQueryInformationToken(TokenHandle, TokenPrivileges, OutputBuffer, OutputBufferLength, &ReturnLength);
				if (NT_SUCCESS(Status))
				{
					DbgPrint("NtQueryInformationToken Success\r\n");

				}
				else if (Status == STATUS_BUFFER_TOO_SMALL)
				{
					DbgPrint("Memory Too Small\r\n");
				}
			}
			if (TokenHandle)
			{
				NtClose(TokenHandle);
			}
			if (ProcessHandle)
			{
				NtClose(ProcessHandle);
			}

			*PreviousMode = Temp;
			//ChangeThreadMode(EThread, PreviousMode);
		}
	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	return Status;
}


NTSTATUS 
AdjustProcessTokenPrivileges(OUT PPRIVILEGE_DATA PrivilegeData, OUT int *bFeedBack)
{
	NTSTATUS  Status;
	PEPROCESS EProcess = NULL;
	HANDLE    hProcess = NULL;
	HANDLE    hToken = NULL;

	if (PrivilegeData->ProcessId)
	{
		DbgPrint("PID: %d\r\n", PrivilegeData->ProcessId);
		DbgPrint("ATT: %d\r\n", PrivilegeData->TokenPrivileges.Privileges->Attributes);

		Status = PsLookupProcessByProcessId((HANDLE)PrivilegeData->ProcessId, &EProcess);
		if (NT_SUCCESS(Status) && IsValidProcess(EProcess))
		{
			// 通过进程体结构获得进程句柄

			HANDLE ProcessHandle = NULL;

			Status = ObOpenObjectByPointer(EProcess,
				OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
				NULL,
				GENERIC_ALL,
				*PsProcessType,
				KernelMode,
				&ProcessHandle);
			if (NT_SUCCESS(Status))
			{
				PETHREAD EThread = NULL;
				UINT8    PreviousMode = 0;
				HANDLE   TokenHandle = NULL;

				EThread = PsGetCurrentThread();
				PreviousMode = ChangeThreadMode(EThread, KernelMode);

				Status = NtOpenProcessToken(ProcessHandle, SACL_SECURITY_INFORMATION, &TokenHandle);
				if (NT_SUCCESS(Status))
				{
					Status = NtAdjustPrivilegesToken(TokenHandle, FALSE,
						&PrivilegeData->TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
					if (NT_SUCCESS(Status))
					{
						*bFeedBack = 1;
						DbgPrint("NtAdjustPrivilegesToken Success\r\n");
					}
				}
				if (TokenHandle)
				{
					NtClose(TokenHandle);
				}
				if (ProcessHandle)
				{
					NtClose(ProcessHandle);
				}

				ChangeThreadMode(EThread, PreviousMode);
			}
		}

		if (EProcess)
		{
			ObDereferenceObject(EProcess);
		}
	}
	return Status;
}

