/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include "PCHunterDrv.h"

DYNAMIC_DATA	g_DynamicData = { 0 };

PDRIVER_OBJECT  g_DriverObject = NULL;

PEPROCESS       g_SystemEProcess = NULL;

NTSTATUS
	DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	PDEVICE_OBJECT  DeviceObject;
	NTSTATUS        Status;
	int             i = 0;

	UNICODE_STRING  DeviceName;
	UNICODE_STRING  LinkName;

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&LinkName, LINK_NAME);

	//创建设备对象;

	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = IoCreateSymbolicLink(&LinkName, &DeviceName);

	for (i = 0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DefaultPassThrough;
	}
	
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlPassThrough;

	DriverObject->DriverUnload = UnloadDriver;
	
	Status = InitDynamicData(&g_DynamicData);			// 初始化信息

	g_DriverObject = DriverObject;

	g_SystemEProcess = PsGetCurrentProcess();

	return STATUS_SUCCESS;
}

/************************************************************************
*  Name : InitDynamicData
*  Param: DynamicData			信息
*  Ret  : NTSTATUS
*  初始化信息
************************************************************************/
NTSTATUS
InitDynamicData(IN OUT PDYNAMIC_DATA DynamicData)
{
	NTSTATUS				Status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW	VersionInfo = { 0 };
	VersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

	if (DynamicData == NULL)
	{
		return STATUS_INVALID_ADDRESS;
	}

	RtlZeroMemory(DynamicData, sizeof(DYNAMIC_DATA));

	// 获得计算机版本信息
	Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&VersionInfo);
	if (Status == STATUS_SUCCESS)
	{
		UINT32 Version = (VersionInfo.dwMajorVersion << 8) | (VersionInfo.dwMinorVersion << 4) | VersionInfo.wServicePackMajor;
		DynamicData->WinVersion = (eWinVersion)Version;

		DbgPrint("%x\r\n", DynamicData->WinVersion);

		switch (Version)
		{
		case WINVER_7:
		case WINVER_7_SP1:
		{
#ifdef _WIN64
			DynamicData->ThreadListHead_KPROCESS = 0x030;
			DynamicData->ObjectTable = 0x200;
			DynamicData->SectionObject = 0x268;
			DynamicData->InheritedFromUniqueProcessId = 0x290;
			DynamicData->ThreadListHead_EPROCESS = 0x308;

			//////////////////////////////////////////////////////////////////////////
			// Thread

			DynamicData->Priority = 0x07b;
			DynamicData->Teb = 0x0b8;
			DynamicData->ContextSwitches = 0x134;
			DynamicData->State = 0x164;
			DynamicData->PreviousMode = 0x1f6;
			DynamicData->Process = 0x210;
			DynamicData->ThreadListEntry_KTHREAD = 0x2f8;
			DynamicData->StartAddress = 0x390;    ////
			DynamicData->Cid = 0x3b8;		////
			DynamicData->Win32StartAddress = 0x418;    ////
			DynamicData->ThreadListEntry_ETHREAD = 0x428;   ////
			DynamicData->SameThreadApcFlags = 0x458;    ////
			
			DynamicData->SizeOfObjectHeader = 0x030;

			DynamicData->KernelStartAddress = 0xFFFF800000000000;
			
			DynamicData->UserEndAddress = 0x00007FFFFFFFFFFF;
			
			DynamicData->HandleTableEntryOffset = 0x010;



	//		DynamicData->NtProtectVirtualMemoryIndex = 0x4D;
	//		DynamicData->NtReadVirtualMemoryIndex = 0x3C;
	//		DynamicData->NtWriteVirtualMemoryIndex = 0x37;

/*			DynamicData->NtQueryVirtualMemoryIndex = 0x20;
			DynamicData->NtProtectVirtualMemoryIndex = 0x4D;
			DynamicData->NtReadVirtualMemoryIndex = 0x3C;
			DynamicData->NtWriteVirtualMemoryIndex = 0x37;
*/
#else
/*			DynamicData->ObjectTable = 0x0f4;
			DynamicData->SectionObject = 0x128;
			DynamicData->InheritedFromUniqueProcessId = 0x140;
			DynamicData->ThreadListHead = 0x02C;
			DynamicData->PreviousMode = 0x13a;
			DynamicData->Process = 0x150;
			DynamicData->ThreadListEntry = 0x1e0;
			

			DynamicData->SizeOfObjectHeader = 0x018;  // Y

			DynamicData->HandleTableEntryOffset = 0x008;

			
			DynamicData->UserEndAddress = 0x80000000;
			DynamicData->NtQueryVirtualMemoryIndex = 0x10B;
			DynamicData->NtProtectVirtualMemoryIndex = 0x0D7;
			DynamicData->NtReadVirtualMemoryIndex = 0x115;
			DynamicData->NtWriteVirtualMemoryIndex = 0x18F;
*/
#endif
			break;
		}
		default:
			break;
		}

		GetSSDTFunctionIndex("NtQueryVirtualMemory", &(DynamicData->NtQueryVirtualMemoryIndex));

		GetSSDTFunctionIndex("NtOpenDirectoryObject", &(DynamicData->NtOpenDirectoryObjectIndex));


	}

	return Status;
}

NTSTATUS
	DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID
	UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING  LinkName;
	PDEVICE_OBJECT	NextDeviceObject    = NULL;
	PDEVICE_OBJECT  CurrentDeviceObject = NULL;
	RtlInitUnicodeString(&LinkName, LINK_NAME);

	IoDeleteSymbolicLink(&LinkName);
	CurrentDeviceObject = DriverObject->DeviceObject;
	while (CurrentDeviceObject != NULL) 
	{
	
		NextDeviceObject = CurrentDeviceObject->NextDevice;
		IoDeleteDevice(CurrentDeviceObject);
		CurrentDeviceObject = NextDeviceObject;
	}

	DbgPrint("PCHunterDrv IS STOPPED!!!");
}