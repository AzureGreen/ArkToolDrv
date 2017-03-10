#include "ProcessCore.h"

extern DYNAMIC_DATA	g_DynamicData;

UINT32  g_SelfProcessId = 0;

typedef
UINT_PTR
	(*pfnObGetObjectType)(PVOID Object);


UINT8
ChangeThreadMode(IN PETHREAD EThread, IN UINT8 WantedMode)
{
	// 保存原先模式
	UINT8 PreviousMode = *((PUINT8)EThread + g_DynamicData.PreviousMode);
	// 修改为WantedMode
	*((PUINT8)EThread + g_DynamicData.PreviousMode) = WantedMode;
	return PreviousMode;
}




/************************************************************************
*  Name : IsValidProcess
*  Param: EProcess				进程体对象
*  Ret  : BOOLEAN
*  判断是否为合法进程 TRUE合法/ FALSE非法
************************************************************************/

BOOLEAN
IsValidProcess(IN PEPROCESS EProcess)
{
	UINT_PTR    ObjectType;
	BOOLEAN		bOk = FALSE;

	UINT_PTR	ProcessType = ((UINT_PTR)*PsProcessType);		// 导出全局变量，进程对象类型

	if (ProcessType && EProcess && MmIsAddressValid((PVOID)(EProcess)))
	{
		ObjectType = KeGetObjectType((PVOID)EProcess);   //*PsProcessType 

		if (ObjectType &&
			ObjectType == ProcessType &&
			IsActiveProcess(EProcess))
		{
			bOk = TRUE;
		}
	}

	return bOk;
}

/************************************************************************
*  Name : IsActiveProcess
*  Param: Object				对象体首地址
*  Ret  : BOOLEAN
*  通过是否存在句柄表判断进程是否存活 TRUE存活/ FALSE死进程
************************************************************************/

BOOLEAN
IsActiveProcess(IN PEPROCESS EProcess)
{
	BOOLEAN bOk = FALSE;

	if (EProcess &&
		MmIsAddressValid(EProcess) &&
		MmIsAddressValid((PVOID)((PUINT8)EProcess + g_DynamicData.ObjectTable)))
	{
		PVOID ObjectTable = *(PVOID*)((PUINT8)EProcess + g_DynamicData.ObjectTable);

		if (ObjectTable &&
			MmIsAddressValid(ObjectTable))
		{
			bOk = TRUE;
		}
	}

	return bOk;
}

/************************************************************************
*  Name : KeGetObjectType
*  Param: Object				对象体首地址
*  Ret  : UINT_PTR				（对象类型）
*  x64：通过ObGetObjectType获得对象类型/ x86：通过ObjectHeader->TypeIndex获得对象类型
************************************************************************/

UINT_PTR
KeGetObjectType(IN PVOID Object)
{
	BOOLEAN		bOk = FALSE;
	UINT_PTR	ObjectType = 0;

	//#ifdef _WIN64
	pfnObGetObjectType	ObGetObjectTypeAddress = NULL;
	if (!MmIsAddressValid || !Object || !MmIsAddressValid(Object))
	{
		return 0;
	}

	bOk = GetNtosExportVariableAddress(L"ObGetObjectType", (PVOID*)&ObGetObjectTypeAddress);

	if (ObGetObjectTypeAddress)
	{
		ObjectType = ObGetObjectTypeAddress(Object);
	}

	return ObjectType;
}

/************************************************************************
*  Name : GetNtosExportVariableAddress
*  Param: wzVariableName		目标变量名称   （双字）
*  Param: VariableAddress		目标变量地址 （OUT）
*  Ret  : BOOLEAN
*  通过全局变量（函数地址）名称返回Ntos导出表中全局变量（函数地址）地址，这里用于 x86下获得SSDT地址
************************************************************************/

BOOLEAN
GetNtosExportVariableAddress(IN WCHAR* wzVariableName, OUT PVOID* VariableAddress)
{
	UNICODE_STRING	uniVariableName = { 0 };

	if (wzVariableName && wcslen(wzVariableName) > 0)
	{
		RtlInitUnicodeString(&uniVariableName, wzVariableName);

		//从Ntoskrnl模块的导出表中获得一个导出变量的地址
		*VariableAddress = MmGetSystemRoutineAddress(&uniVariableName);		// 函数返回值是PVOID，才产生了二维指针
	}

	if (*VariableAddress == NULL)
	{
		return FALSE;
	}

	return TRUE;
}

PEPROCESS
GetIdleEProcess()
{
	UINT_PTR IdleEProcess = 0;
	UINT_PTR PsInitialSystemProcessAddress = (UINT_PTR)&PsInitialSystemProcess;

	if (PsInitialSystemProcessAddress && MmIsAddressValid((PVOID)((PUINT8)PsInitialSystemProcessAddress + 0xA0)))
	{
		IdleEProcess = *(PUINT_PTR)((PUINT8)PsInitialSystemProcessAddress + 0xA0);
		if (IdleEProcess <= 0xffff)
		{
			IdleEProcess = *(PUINT_PTR)((PUINT8)PsInitialSystemProcessAddress + 0xB0);
		}
	}
	return (PEPROCESS)IdleEProcess;
}

UINT_PTR
GetParentProcessIdByEProcess(IN PEPROCESS EProcess)
{
	if (MmIsAddressValid &&
		EProcess &&
		MmIsAddressValid(EProcess) &&
		MmIsAddressValid((PVOID)((PUINT8)EProcess + g_DynamicData.ObjectTable)))
	{
		UINT_PTR  ParentProcessId = 0;

		ParentProcessId = *(PUINT_PTR)((PUINT8)EProcess + g_DynamicData.InheritedFromUniqueProcessId);

		return ParentProcessId;
	}

	return 0;
}

/************************************************************************
*  Name : GetProcessFullPathByProcessId
*  Param: ProcessId					进程Id				（IN）
*  Param: ProcessFullPath			进程完整路径		（OUT）
*  Param: ProcessFullPathLength		进程完整路径字符长度（OUT）
*  Ret  : NTSTATUS
*  通过ZwQueryInformationProcess获得进程完整路径
************************************************************************/

NTSTATUS
GetProcessFullPathByProcessId(IN UINT32 ProcessId, OUT PWCHAR ProcessFullPath, OUT PUINT32 ProcessFullPathLength)
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	HANDLE		ProcessHandle = NULL;
	OBJECT_ATTRIBUTES	oa = { 0 };
	CLIENT_ID	ClientId = { 0 };

	ClientId.UniqueProcess = (HANDLE)ProcessId;

	Status = ZwOpenProcess(&ProcessHandle, GENERIC_ALL, &oa, &ClientId);
	if (NT_SUCCESS(Status))
	{
		PEPROCESS EProcess = NULL;

		// 将句柄转换成对象
		Status = ObReferenceObjectByHandle(ProcessHandle,
			GENERIC_ALL,
			NULL,
			KernelMode,
			(PVOID*)&EProcess,
			NULL);

		if (NT_SUCCESS(Status) && IsValidProcess(EProcess))
		{
			/*
			3: kd> dt _EPROCESS fffffa801ac21060
			nt!_EPROCESS
			+0x000 Pcb              : _KPROCESS
			......
			+0x268 SectionObject    : 0xfffff8a0`01bf2a50 Void
			*/
			PSECTION_OBJECT SectionObject = (PSECTION_OBJECT)(*(PUINT_PTR)((PUINT8)EProcess + g_DynamicData.SectionObject));

			if (SectionObject && MmIsAddressValid(SectionObject))
			{
				/*
				3: kd> dt _SECTION_OBJECT 0xfffff8a0`01bf2a50
				nt!_SECTION_OBJECT
				+0x000 StartingVa       : (null)
				+0x008 EndingVa         : 0xfffff880`037fcba8 Void
				+0x010 Parent           : 0xfffff880`037fcb90 Void
				+0x018 LeftChild        : (null)
				+0x020 RightChild       : 0xfffffa80`1ac18d40 Void
				+0x028 Segment          : 0xfffff8a0`01deb000 _SEGMENT_OBJECT
				*/
				PSEGMENT Segment = SectionObject->Segment;

				if (Segment && MmIsAddressValid(Segment))
				{
					/*
					3: kd> dt _SEGMENT 0xfffff8a0`01deb000
					nt!_SEGMENT
					+0x000 ControlArea      : 0xfffffa80`1ac18800 _CONTROL_AREA
					+0x008 TotalNumberOfPtes : 0x2c0
					+0x00c SegmentFlags     : _SEGMENT_FLAGS
					+0x010 NumberOfCommittedPages : 0
					+0x018 SizeOfSegment    : 0x2c0000
					+0x020 ExtendInfo       : 0x00000000`ff9f0000 _MMEXTEND_INFO
					+0x020 BasedAddress     : 0x00000000`ff9f0000 Void
					+0x028 SegmentLock      : _EX_PUSH_LOCK
					+0x030 u1               : <unnamed-tag>
					+0x038 u2               : <unnamed-tag>
					+0x040 PrototypePte     : 0xfffff8a0`01deb048 _MMPTE
					+0x048 ThePtes          : [1] _MMPTE
					*/
					PCONTROL_AREA ControlArea = Segment->ControlArea;

					if (ControlArea && MmIsAddressValid(ControlArea))
					{
						/*
						3: kd> dt _CONTROL_AREA 0xfffffa80`1ac18800
						nt!_CONTROL_AREA
						+0x000 Segment          : 0xfffff8a0`01deb000 _SEGMENT
						+0x008 DereferenceList  : _LIST_ENTRY [ 0x00000000`00000000 - 0x0 ]
						+0x018 NumberOfSectionReferences : 1
						+0x020 NumberOfPfnReferences : 0xb7
						+0x028 NumberOfMappedViews : 1
						+0x030 NumberOfUserReferences : 2
						+0x038 u                : <unnamed-tag>
						+0x03c FlushInProgressCount : 0
						+0x040 FilePointer      : _EX_FAST_REF
						+0x048 ControlAreaLock  : 0n0
						+0x04c ModifiedWriteCount : 0
						+0x04c StartingFrame    : 0
						+0x050 WaitingForDeletion : (null)
						+0x058 u2               : <unnamed-tag>
						+0x068 LockedPages      : 0n1
						+0x070 ViewList         : _LIST_ENTRY [ 0xfffffa80`1acf3230 - 0xfffffa80`1acf3230 ]

						3: kd> dq 0xfffffa80`1ac18800+40
						fffffa80`1ac18840  fffffa80`1ac18d44 00000000`00000000
						*/
						PFILE_OBJECT FileObject = (UINT_PTR)ControlArea->FilePointer & 0xFFFFFFFFFFFFFFF0;

						if (FileObject && MmIsAddressValid(FileObject))
						{
							POBJECT_NAME_INFORMATION    oni = NULL;
							/*
							3: kd> dt _FILE_OBJECT fffffa80`1ac18d40
							nt!_FILE_OBJECT
							+0x000 Type             : 0n5
							+0x002 Size             : 0n216
							+0x008 DeviceObject     : 0xfffffa80`192fd4c0 _DEVICE_OBJECT
							+0x010 Vpb              : 0xfffffa80`1923d370 _VPB
							+0x018 FsContext        : 0xfffff8a0`01dbb140 Void
							+0x020 FsContext2       : 0xfffff8a0`01bf1ec0 Void
							+0x028 SectionObjectPointer : 0xfffffa80`1ac25328 _SECTION_OBJECT_POINTERS
							+0x030 PrivateCacheMap  : (null)
							+0x038 FinalStatus      : 0n0
							+0x040 RelatedFileObject : (null)
							+0x048 LockOperation    : 0 ''
							+0x049 DeletePending    : 0 ''
							+0x04a ReadAccess       : 0x1 ''
							+0x04b WriteAccess      : 0 ''
							+0x04c DeleteAccess     : 0 ''
							+0x04d SharedRead       : 0x1 ''
							+0x04e SharedWrite      : 0 ''
							+0x04f SharedDelete     : 0x1 ''
							+0x050 Flags            : 0x44042
							+0x058 FileName         : _UNICODE_STRING "\Windows\explorer.exe"
							*/
							Status = IoQueryFileDosDeviceName(FileObject, &oni);
							if (NT_SUCCESS(Status))
							{
								if (oni->Name.Length >= MAX_PATH)
								{
									*ProcessFullPathLength = MAX_PATH - 1;
								}
								else
								{
									*ProcessFullPathLength = oni->Name.Length * sizeof(WCHAR);
								}

								RtlCopyMemory(ProcessFullPath, oni->Name.Buffer, *ProcessFullPathLength);

								Status = STATUS_SUCCESS;

								DbgPrint("%S\r\n", ProcessFullPath);
							}
						}
					}
				}
			}
		}

		if (EProcess)
		{
			ObDereferenceObject(EProcess);
		}

		ZwClose(ProcessHandle);
	}

	return Status;
}


NTSTATUS
SetSelfProcessId(IN UINT32 ProcessId, OUT PVOID OutputBuffer, OUT PUINT32 OutputBufferLength)
{
	g_SelfProcessId = ProcessId;
	DbgPrint("Self Process Id: %d\r\n", g_SelfProcessId);
	*(PUINT32)OutputBuffer = 8080;
	*OutputBufferLength = sizeof(UINT32);

	return STATUS_SUCCESS;
}

NTSTATUS 
GetSystemProcessCount(OUT PVOID OutputBuffer, OUT PUINT32 OutputBufferLength)
{
	NTSTATUS    Status = STATUS_SUCCESS;
	UINT32      ProcessId = 0;
	PEPROCESS   EProcess = NULL;
	UINT32      ProcessCount = 0;

	for (ProcessId = 0; ProcessId < MAX_PROCESS_COUNT; ProcessId += 4)
	{
		if (ProcessId == 0 || ProcessId == g_SelfProcessId)
		{
			ProcessCount++;
			continue;
		}
		
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
		if (NT_SUCCESS(Status) && IsValidProcess(EProcess))
		{
			ProcessCount++;
		}

		if (EProcess)
		{
			ObDereferenceObject(EProcess);
		}
	}

	*(PUINT32)OutputBuffer = ProcessCount;
	*OutputBufferLength = sizeof(UINT32);

	return Status;
}

NTSTATUS 
EnumSystemProcessList(IN UINT32 BaseProcessId, OUT PVOID OutputBuffer, OUT PUINT32 OutputBufferLength)
{
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;
	UINT32    ProcessId = 0;
	CLIENT_ID ClientId = { 0 };
	PEPROCESS EProcess = NULL;

	PROCESS_INFORMATION ProcessInfo = { 0 };

	for (ProcessId = BaseProcessId; ProcessId < MAX_PROCESS_COUNT; ProcessId += 4)
	{
		ClientId.UniqueProcess = (HANDLE)ProcessId;

		if (ProcessId == 0)
		{
			// Idle
			ProcessInfo.ProcessId = 0;
			ProcessInfo.ParentProcessId = 0;
			ProcessInfo.Eprocess = (UINT_PTR)GetIdleEProcess();
			break;
		}
		else if (ProcessId == g_SelfProcessId)
		{
			// 当前自己进程
			EProcess = PsGetCurrentProcess();
		}
		else
		{
			// 其他进程
			PsLookupProcessByProcessId((HANDLE)ProcessId, &EProcess);
		}

		if (IsValidProcess(EProcess))
		{
			UINT32 ProcessFullPathLength = 0;

			ProcessInfo.ProcessId = ProcessId;
			ProcessInfo.Eprocess = (UINT_PTR)EProcess;
			ProcessInfo.ParentProcessId = (UINT32)GetParentProcessIdByEProcess(EProcess);

			GetProcessFullPathByProcessId(ProcessId, ProcessInfo.wzFileFullPath, &ProcessFullPathLength);
			break;
		}

	}

	if (EProcess)
	{
		ObDereferenceObject(EProcess);
	}

	if (ProcessId > MAX_PROCESS_COUNT)
	{
		ProcessInfo.Eprocess = 0;
		ProcessInfo.ParentProcessId = 0;
		*OutputBufferLength = 0;
		memcpy(OutputBuffer, &ProcessInfo, sizeof(ProcessInfo));
		Status = STATUS_UNSUCCESSFUL;
	}
	else
	{
		*OutputBufferLength = sizeof(ProcessInfo);
		memcpy(OutputBuffer, &ProcessInfo, *OutputBufferLength);
		Status = STATUS_SUCCESS;
	}

	return Status;
}
