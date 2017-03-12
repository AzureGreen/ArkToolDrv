#include "ModuleCore.h"


typedef
NTSTATUS
(*pfnNtOpenDirectoryObject)(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes);


extern PDRIVER_OBJECT  g_DriverObject;
extern DYNAMIC_DATA    g_DynamicData;


POBJECT_TYPE g_DirectoryObjectType = NULL;


PLDR_DATA_TABLE_ENTRY
GetKernelLdrDataTableEntry(IN PDRIVER_OBJECT DriverObject)
{
	PLDR_DATA_TABLE_ENTRY TravelEntry = NULL, FirstEntry = NULL;

	if (DriverObject)
	{	
		WCHAR wzNtoskrnl[] = L"ntoskrnl.exe";
		int   iLength = wcslen(wzNtoskrnl) * sizeof(WCHAR);

		FirstEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

		for (TravelEntry = (PLDR_DATA_TABLE_ENTRY)FirstEntry->InLoadOrderLinks.Flink;
			TravelEntry != FirstEntry;
			TravelEntry = (PLDR_DATA_TABLE_ENTRY)TravelEntry->InLoadOrderLinks.Flink)
		{
			if (TravelEntry->BaseDllName.Buffer &&
				TravelEntry->BaseDllName.Length == iLength &&
				MmIsAddressValid((PVOID)TravelEntry->BaseDllName.Buffer) &&
					!_wcsnicmp(wzNtoskrnl, (WCHAR*)TravelEntry->BaseDllName.Buffer, iLength / sizeof(WCHAR)))
			{
				return TravelEntry;
			}
		}

		// 没找到
		return FirstEntry;
	}
	return NULL;
}


// 通过遍历Ldr枚举内核模块
VOID
EnumKernelModuleByLdrDataTableEntry(IN PLDR_DATA_TABLE_ENTRY KernelLdrEntry, OUT PKERNEL_MODULE_INFORMATION kmi, IN UINT32 NumberOfDrivers)
{
	PLDR_DATA_TABLE_ENTRY TravelEntry = KernelLdrEntry;

	if (kmi && TravelEntry)
	{
		KIRQL OldIrql;

		OldIrql = KeRaiseIrqlToDpcLevel();

		__try
		{
			UINT32 MaxSize = PAGE_SIZE;
			INT32  i = 0;

			do 
			{
				if ((UINT_PTR)TravelEntry->DllBase > g_DynamicData.KernelStartAddress && TravelEntry->SizeOfImage > 0)
				{
					UINT_PTR CurrentCount = kmi->NumberOfDrivers;
					if (NumberOfDrivers > CurrentCount)
					{

						kmi->Drivers[CurrentCount].LoadOrder = ++i;
						kmi->Drivers[CurrentCount].BaseAddress = (UINT_PTR)TravelEntry->DllBase;
						kmi->Drivers[CurrentCount].Size = TravelEntry->SizeOfImage;


						if (IsUnicodeStringValid(&(TravelEntry->FullDllName)))
						{
							memcpy(kmi->Drivers[CurrentCount].wzDriverPath, (WCHAR*)TravelEntry->FullDllName.Buffer, TravelEntry->FullDllName.Length);
						}
						else if (IsUnicodeStringValid(&(TravelEntry->BaseDllName)))
						{
							memcpy(kmi->Drivers[CurrentCount].wzDriverPath, (WCHAR*)TravelEntry->BaseDllName.Buffer, TravelEntry->BaseDllName.Length);
						}
					}
					kmi->NumberOfDrivers++;
				}
				TravelEntry = (PLDR_DATA_TABLE_ENTRY)TravelEntry->InLoadOrderLinks.Flink;

			} while (TravelEntry && TravelEntry != KernelLdrEntry && MaxSize--);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{ }

		KeLowerIrql(OldIrql);
	}
}


// 查看传入的对象是否已经存在结构体中，如果在 则继续完善信息，如果不在，则返回false，留给母程序处理
BOOLEAN 
IsDriverInList(IN PKERNEL_MODULE_INFORMATION kmi, IN PDRIVER_OBJECT DriverObject, IN UINT32 NumberOfDrivers)
{
	BOOLEAN bOk = TRUE, bFind = FALSE;

	if (!kmi || !DriverObject || !MmIsAddressValid(DriverObject))
	{
		return bOk;
	}

	__try
	{
		if (MmIsAddressValid(DriverObject))
		{
			PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

			if (LdrDataTableEntry &&
				MmIsAddressValid(LdrDataTableEntry) &&
				MmIsAddressValid((PVOID)LdrDataTableEntry->DllBase) &&
				(UINT_PTR)LdrDataTableEntry->DllBase > g_DynamicData.KernelStartAddress)
			{
				UINT32 i = 0;
				UINT32 Count = NumberOfDrivers > kmi->NumberOfDrivers ? kmi->NumberOfDrivers : NumberOfDrivers;

				for (i = 0; i < Count; i++)
				{
					if (kmi->Drivers[i].BaseAddress == (UINT_PTR)LdrDataTableEntry->DllBase)
					{
						if (kmi->Drivers[i].DriverObject == 0)
						{
							// 获得驱动对象
							kmi->Drivers[i].DriverObject = (UINT_PTR)DriverObject;

							// 获得驱动入口
							kmi->Drivers[i].DirverStartAddress = (UINT_PTR)LdrDataTableEntry->EntryPoint;

							// 获得服务名
							wcsncpy(kmi->Drivers[i].wzKeyName, DriverObject->DriverExtension->ServiceKeyName.Buffer, DriverObject->DriverExtension->ServiceKeyName.Length);
						}

						bFind = TRUE;
						break;
					}
				}

				if (bFind == FALSE)
				{
					bOk = FALSE;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		bOk = TRUE;
	}

	return bOk;
}


VOID 
InsertDriver(OUT PKERNEL_MODULE_INFORMATION kmi, IN PDRIVER_OBJECT DriverObject, IN UINT32 NumberOfDrivers)
{
	if (!kmi || !DriverObject || !MmIsAddressValid(DriverObject))
	{
		return;
	}
	else
	{
		PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

		if (LdrDataTableEntry &&
			MmIsAddressValid(LdrDataTableEntry) &&
			MmIsAddressValid((PVOID)LdrDataTableEntry->DllBase) &&
			(UINT_PTR)LdrDataTableEntry->DllBase > g_DynamicData.KernelStartAddress)
		{
			UINT32 Count = kmi->NumberOfDrivers;

			if (NumberOfDrivers > Count)
			{
				kmi->Drivers[Count].BaseAddress = (UINT_PTR)LdrDataTableEntry->DllBase;
				kmi->Drivers[Count].Size = LdrDataTableEntry->SizeOfImage;
				kmi->Drivers[Count].DriverObject = (UINT_PTR)DriverObject;

				if (IsUnicodeStringValid(&(LdrDataTableEntry->FullDllName)))
				{
					wcsncpy(kmi->Drivers[Count].wzDriverPath, (WCHAR*)(LdrDataTableEntry->FullDllName.Buffer), LdrDataTableEntry->FullDllName.Length);
				}
				else if (IsUnicodeStringValid(&(LdrDataTableEntry->BaseDllName)))
				{
					wcsncpy(kmi->Drivers[Count].wzDriverPath, (WCHAR*)(LdrDataTableEntry->BaseDllName.Buffer), LdrDataTableEntry->BaseDllName.Length);
				}
			}
			kmi->NumberOfDrivers++;
		}
	}
}

// 遍历哈希目录 --> 目录上每个链表 --> 1.目录 递归  2.驱动对象 插入  3.设备对象 遍历设备栈 插入驱动对象
VOID
TravelDirectoryObject(IN PVOID DirectoryObject, OUT PKERNEL_MODULE_INFORMATION kmi, IN UINT32 NumberOfDrivers)
{

	if (kmi	&& DirectoryObject && MmIsAddressValid(DirectoryObject))
	{
		ULONG i = 0;
		POBJECT_DIRECTORY ObjectDirectory = (POBJECT_DIRECTORY)DirectoryObject;
		KIRQL OldIrql = KeRaiseIrqlToDpcLevel();	// 提高中断级别

		__try
		{
			// 哈希表
			for (i = 0; i < NUMBER_HASH_BUCKETS; i++)	 // 遍历数组结构 每个数组成员都有一条链表
			{
				POBJECT_DIRECTORY_ENTRY ObjectDirectoryEntry = ObjectDirectory->HashBuckets[i];

				// 所以此处再次遍历链表结构
				for (; (UINT_PTR)ObjectDirectoryEntry > g_DynamicData.KernelStartAddress && MmIsAddressValid(ObjectDirectoryEntry);
					ObjectDirectoryEntry = ObjectDirectoryEntry->ChainLink)	
				{
					if (MmIsAddressValid(ObjectDirectoryEntry->Object))
					{
						POBJECT_TYPE ObjectType = KeGetObjectType(ObjectDirectoryEntry->Object);

						//
						// 如果是目录，那么继续递归遍历
						//
						if (ObjectType == g_DirectoryObjectType)
						{
							TravelDirectoryObject(ObjectDirectoryEntry->Object, kmi, NumberOfDrivers);
						}

						//
						// 如果是驱动对象
						//
						else if (ObjectType == *IoDriverObjectType)
						{
							PDEVICE_OBJECT DeviceObject = NULL;

							if (!IsDriverInList(kmi, (PDRIVER_OBJECT)ObjectDirectoryEntry->Object, NumberOfDrivers))
							{
								InsertDriver(kmi, (PDRIVER_OBJECT)ObjectDirectoryEntry->Object, NumberOfDrivers);
							}

							//
							// 遍历设备栈！！！
							//
							for (DeviceObject = ((PDRIVER_OBJECT)ObjectDirectoryEntry->Object)->DeviceObject;
								DeviceObject && MmIsAddressValid(DeviceObject);
								DeviceObject = DeviceObject->AttachedDevice)
							{
								if (!IsDriverInList(kmi, DeviceObject->DriverObject, NumberOfDrivers))
								{
									InsertDriver(kmi, DeviceObject->DriverObject, NumberOfDrivers);
								}
							}
						}

						//
						// 如果是设备对象
						//
						else if (ObjectType == *IoDeviceObjectType)
						{
							PDEVICE_OBJECT DeviceObject = NULL;

							if (!IsDriverInList(kmi, ((PDEVICE_OBJECT)ObjectDirectoryEntry->Object)->DriverObject, NumberOfDrivers))
							{
								InsertDriver(kmi, ((PDEVICE_OBJECT)ObjectDirectoryEntry->Object)->DriverObject, NumberOfDrivers);
							}

							//
							// 遍历设备栈
							//
							for (DeviceObject = ((PDEVICE_OBJECT)ObjectDirectoryEntry->Object)->AttachedDevice;
								DeviceObject && MmIsAddressValid(DeviceObject);
								DeviceObject = DeviceObject->AttachedDevice)
							{
								if (!IsDriverInList(kmi, DeviceObject->DriverObject, NumberOfDrivers))
								{
									InsertDriver(kmi, DeviceObject->DriverObject, NumberOfDrivers);
								}
							}
						}
					}
				}
			}
		}
		__except (1)
		{
		}

		KeLowerIrql(OldIrql);
	}
}

VOID 
EnumKernelModuleByDirectoryObject(OUT PKERNEL_MODULE_INFORMATION kmi, IN UINT32 NumberOfDrivers)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE   DirectoryHandle = NULL;

	UINT8    PreviousMode = 0;
	PETHREAD EThread = NULL;

	WCHAR             wzDirectory[] = { L'\\', L'\0' };
	UNICODE_STRING    uniDirectory = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };

	RtlInitUnicodeString(&uniDirectory, wzDirectory);
	InitializeObjectAttributes(&oa, &uniDirectory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	EThread = PsGetCurrentThread();
	PreviousMode = ChangeThreadMode(EThread, KernelMode);

	pfnNtOpenDirectoryObject NtOpenDirectoryObject = GetSSDTEntry(g_DynamicData.NtOpenDirectoryObjectIndex);

	Status = NtOpenDirectoryObject(&DirectoryHandle, 0, &oa);

	DbgPrint("NtOpenDirectoryObject  %x\r\n", Status);

	if (NT_SUCCESS(Status))
	{
		PVOID  DirectoryObject = NULL;

		// 将句柄转为对象
		Status = ObReferenceObjectByHandle(DirectoryHandle, GENERIC_ALL, NULL, KernelMode, &DirectoryObject, NULL);
		if (NT_SUCCESS(Status))
		{
			g_DirectoryObjectType = KeGetObjectType(DirectoryObject);		// 全局保存目录对象类型 便于后续比较

			TravelDirectoryObject(DirectoryObject, kmi, NumberOfDrivers);
			ObfDereferenceObject(DirectoryObject);
		}

		Status = NtClose(DirectoryHandle);
	}

	PreviousMode = ChangeThreadMode(EThread, PreviousMode);
}


NTSTATUS
EnumSystemModuleList(OUT PVOID OutputBuffer, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UINT32	NumberOfDrivers = (OutputLength - sizeof(KERNEL_MODULE_INFORMATION)) / sizeof(KERNEL_MODULE_ENTRY_INFORMATION);		// Ring3传递Length

	if (OutputBuffer != NULL)
	{
		PLDR_DATA_TABLE_ENTRY KernelLdrEntry = GetKernelLdrDataTableEntry(g_DriverObject);

		EnumKernelModuleByLdrDataTableEntry(KernelLdrEntry, (PKERNEL_MODULE_INFORMATION)OutputBuffer, NumberOfDrivers);

		EnumKernelModuleByDirectoryObject((PKERNEL_MODULE_INFORMATION)OutputBuffer, NumberOfDrivers);

		if (NumberOfDrivers >= ((PKERNEL_MODULE_INFORMATION)OutputBuffer)->NumberOfDrivers)
		{
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_BUFFER_TOO_SMALL;
		}
	}

	return Status;
}


//判断一个驱动是否为真的驱动对象
BOOLEAN 
IsValidDriverObject(IN PDRIVER_OBJECT DriverObject)
{
	BOOLEAN bOk = FALSE;
	if (!*IoDriverObjectType ||
		!*IoDeviceObjectType)
	{
		return bOk;
	}

	__try
	{
		if (DriverObject->Type == 4 &&
			DriverObject->Size == sizeof(DRIVER_OBJECT) &&
			KeGetObjectType(DriverObject) == *IoDriverObjectType &&
			MmIsAddressValid(DriverObject->DriverSection) &&
			(UINT_PTR)DriverObject->DriverSection > g_DynamicData.KernelStartAddress &&
			!(DriverObject->DriverSize & 0x1F) &&
			DriverObject->DriverSize < g_DynamicData.KernelStartAddress &&
			!((UINT_PTR)(DriverObject->DriverStart) & 0xFFF) &&		// 起始地址都是页对齐
			(UINT_PTR)DriverObject->DriverStart > g_DynamicData.KernelStartAddress)
		{
			PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
			if (DeviceObject)
			{
				if (MmIsAddressValid(DeviceObject) &&
					KeGetObjectType(DeviceObject) == *IoDeviceObjectType &&
					DeviceObject->Type == 3 &&
					DeviceObject->Size >= sizeof(DEVICE_OBJECT))
				{
					bOk = TRUE;
				}
			}
			else
			{
				bOk = TRUE;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		bOk = FALSE;
	}

	return bOk;
}


// 调用对象的卸载函数 清理所有派遣例程
VOID 
HaveDriverUnloadThreadCallback(IN PVOID lParam)
{
	PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)lParam;

	if (DriverObject)
	{
		PDRIVER_UNLOAD DriverUnloadAddress = DriverObject->DriverUnload;

		if (DriverUnloadAddress)
		{
			DriverUnloadAddress(DriverObject);

			DriverObject->FastIoDispatch = NULL;		// FastIO
			RtlZeroMemory(DriverObject->MajorFunction, sizeof(DriverObject->MajorFunction));
			DriverObject->DriverUnload = NULL;

			ObMakeTemporaryObject(DriverObject);	// removes the name of the object from its parent directory
			ObfDereferenceObject(DriverObject);
		}
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID 
HaveNoDriverUnloadThreadCallback(IN PVOID lParam)
{

	PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)lParam;
	
	if (DriverObject)
	{
		PDEVICE_OBJECT	NextDeviceObject = NULL;
		PDEVICE_OBJECT  CurrentDeviceObject = NULL;

		DriverObject->FastIoDispatch = NULL;
		RtlZeroMemory(DriverObject->MajorFunction, sizeof(DriverObject->MajorFunction));
		DriverObject->DriverUnload = NULL;

		CurrentDeviceObject = DriverObject->DeviceObject;

		while (CurrentDeviceObject && MmIsAddressValid(CurrentDeviceObject))	// 自己实现Unload 也就是清除设备链
		{
			NextDeviceObject = CurrentDeviceObject->NextDevice;
			IoDeleteDevice(CurrentDeviceObject);
			CurrentDeviceObject = NextDeviceObject;
		}

		ObMakeTemporaryObject(DriverObject);
		ObfDereferenceObject(DriverObject);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

// 创建系统线程 完成卸载函数
NTSTATUS 
PspUnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (MmIsAddressValid(DriverObject))
	{
		BOOLEAN bDriverUnload = FALSE;
		HANDLE  SystemThreadHandle = NULL;

		if (DriverObject->DriverUnload &&
			(UINT_PTR)DriverObject->DriverUnload > g_DynamicData.KernelStartAddress &&
			MmIsAddressValid(DriverObject->DriverUnload))
		{
			bDriverUnload = TRUE;
		}

		if (bDriverUnload)	 // 如果存在卸载函数
		{
			Status = PsCreateSystemThread(&SystemThreadHandle, 0, NULL, NULL, NULL, HaveDriverUnloadThreadCallback, DriverObject);
		}
		else
		{
			Status = PsCreateSystemThread(&SystemThreadHandle, 0, NULL, NULL, NULL, HaveNoDriverUnloadThreadCallback, DriverObject);
		}

		// 等待线程 关闭句柄

		if (NT_SUCCESS(Status))
		{
			PETHREAD EThread = NULL, CurrentEThread = NULL;
			UINT8 PreviousMode = 0;

			Status = ObReferenceObjectByHandle(SystemThreadHandle, 0, NULL, KernelMode, &EThread, NULL);
			if (NT_SUCCESS(Status))
			{
				LARGE_INTEGER TimeOut;
				TimeOut.QuadPart = -10 * 1000 * 1000 * 3;
				Status = KeWaitForSingleObject(EThread, Executive, KernelMode, TRUE, &TimeOut); // 等待3秒
				ObfDereferenceObject(EThread);
			}

			CurrentEThread = PsGetCurrentThread();
			PreviousMode = ChangeThreadMode(CurrentEThread, KernelMode);
			NtClose(SystemThreadHandle);
			ChangeThreadMode(CurrentEThread, PreviousMode);
		}
	}

	return Status;
}

NTSTATUS
UnloadDriverObject(IN PVOID InputBuffer, IN UINT32 InputLength)
{
	PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)InputBuffer;
	NTSTATUS       Status = STATUS_UNSUCCESSFUL;

	if ((UINT_PTR)DriverObject > g_DynamicData.KernelStartAddress &&
		MmIsAddressValid(DriverObject) &&
		g_DriverObject != DriverObject &&
		IsValidDriverObject(DriverObject))
	{
		Status = PspUnloadDriver(DriverObject);
	}

	return Status;
}