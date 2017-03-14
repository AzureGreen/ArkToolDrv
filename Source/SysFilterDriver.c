#include "SysFilterDriver.h"

extern DYNAMIC_DATA	g_DynamicData;

UINT32 g_VolumeStartCount = 0;
UINT32 g_FileSystemStartCount = 0;

// 上层设备对象
// 下层驱动对象
// Ring3Buffer
// Count
// 类型

NTSTATUS 
FillFilterDriverInfo(IN PDEVICE_OBJECT AttachDeviceObject, IN PDRIVER_OBJECT AttachedDriverObject, OUT PFILTER_DRIVER_INFORMATION fdi, IN UINT32 NumberOfFilterDrivers, IN FILTER_TYPE Type)
{
	if (AttachDeviceObject && MmIsAddressValid((PVOID)AttachDeviceObject)
		&& AttachedDriverObject && MmIsAddressValid((PVOID)AttachedDriverObject)
		&& fdi && MmIsAddressValid((PVOID)fdi))
	{
		UINT32 CurrentCount = fdi->NumberOfFilterDrivers;
		if (NumberOfFilterDrivers > CurrentCount)
		{
			PDRIVER_OBJECT        AttachDriverObject = AttachDeviceObject->DriverObject;		// 去挂钩设备的驱动对象（上层）
			PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;

			INT i = 0;

			if (Type == File || Type == Raw)
			{
				if (g_FileSystemStartCount == 0)
				{
					g_FileSystemStartCount = CurrentCount;
				}
				for (i = g_FileSystemStartCount; i < CurrentCount; i++)
				{
					if (_wcsnicmp(fdi->FilterDrivers[i].wzFilterDriverName, AttachDriverObject->DriverName.Buffer, wcslen(fdi->FilterDrivers[i].wzFilterDriverName)) == 0 &&
						_wcsnicmp(fdi->FilterDrivers[i].wzAttachedDriverName, AttachedDriverObject->DriverName.Buffer, wcslen(fdi->FilterDrivers[i].wzAttachedDriverName)) == 0)
					{
						return STATUS_SUCCESS;
					}
				}
			}
			if (Type == Volume)
			{
				if (g_VolumeStartCount == 0)
				{
					g_VolumeStartCount = CurrentCount;
				}
				for (i = 0; i < CurrentCount; i++)
				{
					if (_wcsnicmp(fdi->FilterDrivers[i].wzFilterDriverName, AttachDriverObject->DriverName.Buffer, wcslen(fdi->FilterDrivers[i].wzFilterDriverName)) == 0 &&
						_wcsnicmp(fdi->FilterDrivers[i].wzAttachedDriverName, AttachedDriverObject->DriverName.Buffer, wcslen(fdi->FilterDrivers[i].wzAttachedDriverName)) == 0)
					{
						return STATUS_SUCCESS;
					}
				}

			}

			fdi->FilterDrivers[CurrentCount].Type = Type;
			fdi->FilterDrivers[CurrentCount].FilterDeviceObject = (UINT_PTR)AttachDeviceObject;		
			
			// 挂钩驱动（上层）
			if (IsUnicodeStringValid(&(AttachDriverObject->DriverName)))
			{
				RtlZeroMemory(fdi->FilterDrivers[CurrentCount].wzFilterDriverName, MAX_PATH);
				RtlCopyMemory(fdi->FilterDrivers[CurrentCount].wzFilterDriverName, AttachDriverObject->DriverName.Buffer, AttachDriverObject->DriverName.Length);
			}

			// 被挂钩驱动（下层）
			if (IsUnicodeStringValid(&(AttachedDriverObject->DriverName)))
			{
				RtlZeroMemory(fdi->FilterDrivers[CurrentCount].wzAttachedDriverName, MAX_PATH);
				RtlCopyMemory(fdi->FilterDrivers[CurrentCount].wzAttachedDriverName, AttachedDriverObject->DriverName.Buffer, AttachDriverObject->DriverName.Length);
			}

			LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)AttachDriverObject->DriverSection;

			if ((UINT_PTR)LdrDataTableEntry > g_DynamicData.KernelStartAddress)
			{
				if (IsUnicodeStringValid(&(LdrDataTableEntry->FullDllName)))
				{
					RtlZeroMemory(fdi->FilterDrivers[CurrentCount].wzFilePath, MAX_PATH);
					RtlCopyMemory(fdi->FilterDrivers[CurrentCount].wzFilePath, LdrDataTableEntry->FullDllName.Buffer, LdrDataTableEntry->FullDllName.Length);
				}
				else if (IsUnicodeStringValid(&(LdrDataTableEntry->BaseDllName)))
				{
					RtlZeroMemory(fdi->FilterDrivers[CurrentCount].wzFilePath, MAX_PATH);
					RtlCopyMemory(fdi->FilterDrivers[CurrentCount].wzFilePath, LdrDataTableEntry->BaseDllName.Buffer, LdrDataTableEntry->BaseDllName.Length);
				}
			}
		}
		else
		{
			return STATUS_BUFFER_TOO_SMALL;
		}

		fdi->NumberOfFilterDrivers++;

		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}


NTSTATUS
GetFilterDriverByDriverName(IN WCHAR *wzDriverName, IN  PFILTER_DRIVER_INFORMATION fdi, IN UINT32 NumberOfFilterDrivers, IN FILTER_TYPE Type)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uniDriverName;
	PDRIVER_OBJECT DriverObject = NULL;

	RtlInitUnicodeString(&uniDriverName, wzDriverName);

	Status = ObReferenceObjectByName(
		&uniDriverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&DriverObject);

	if (NT_SUCCESS(Status) && DriverObject && MmIsAddressValid((PVOID)DriverObject))
	{
		PDEVICE_OBJECT DeviceObject = NULL;
		
		// 遍历水平层次结构 NextDevice 设备链
		for (DeviceObject = DriverObject->DeviceObject;
			DeviceObject && MmIsAddressValid((PVOID)DeviceObject);
			DeviceObject = DeviceObject->NextDevice)
		{
			PDRIVER_OBJECT AttachedDriverObject = DeviceObject->DriverObject;
			PDEVICE_OBJECT AttachDeviceObject = NULL;

			// 遍历垂直层次结构 AttachedDevice  设备栈
			for (AttachDeviceObject = DeviceObject->AttachedDevice;
				AttachDeviceObject;
				AttachDeviceObject = AttachDeviceObject->AttachedDevice)
			{
				// AttachDeviceObject --> 去挂载的驱动（上层）
				// AttachedDriverObject --> 被挂载的驱动（下层）
				Status = FillFilterDriverInfo(AttachDeviceObject, AttachedDriverObject, fdi, NumberOfFilterDrivers, Type);
				AttachedDriverObject = AttachDeviceObject->DriverObject;
			}

		}

		ObDereferenceObject(DriverObject);
	}

	return Status;
}


NTSTATUS
EnumFilterDriver(OUT PVOID OutputBuffer, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UINT32   NumberOfFilterDrivers = (OutputLength - sizeof(FILTER_DRIVER_INFORMATION)) / sizeof(FILTER_DRIVER_ENTRY_INFORMATION);

	PFILTER_DRIVER_INFORMATION fdi = (PFILTER_DRIVER_INFORMATION)OutputBuffer;

	// 写上所有的驱动名。

	g_VolumeStartCount = 0;
	g_FileSystemStartCount = 0;

	Status = GetFilterDriverByDriverName(L"\\Driver\\Disk", fdi, NumberOfFilterDrivers, Disk);
	Status = GetFilterDriverByDriverName(L"\\Driver\\volmgr", fdi, NumberOfFilterDrivers, Volume);
	Status = GetFilterDriverByDriverName(L"\\FileSystem\\ntfs", fdi, NumberOfFilterDrivers, File);
	Status = GetFilterDriverByDriverName(L"\\FileSystem\\fastfat", fdi, NumberOfFilterDrivers, File);
	Status = GetFilterDriverByDriverName(L"\\Driver\\kbdclass", fdi, NumberOfFilterDrivers, Keyboard);
	Status = GetFilterDriverByDriverName(L"\\Driver\\mouclass", fdi, NumberOfFilterDrivers, Mouse);
	Status = GetFilterDriverByDriverName(L"\\Driver\\i8042prt", fdi, NumberOfFilterDrivers, I8042prt);
	Status = GetFilterDriverByDriverName(L"\\Driver\\tdx", fdi, NumberOfFilterDrivers, Tdx);
	Status = GetFilterDriverByDriverName(L"\\Driver\\NDIS", fdi, NumberOfFilterDrivers, NDIS);
	Status = GetFilterDriverByDriverName(L"\\Driver\\PnpManager", fdi, NumberOfFilterDrivers, PnpManager);
	Status = GetFilterDriverByDriverName(L"\\FileSystem\\Raw", fdi, NumberOfFilterDrivers, Raw);

	return Status;

}


NTSTATUS
ClearFilters(IN WCHAR *wzDriverName, IN UINT_PTR DeviceObject)
{
	NTSTATUS       Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uniDriverName = { 0 };
	PDRIVER_OBJECT DriverObject = NULL;

	RtlInitUnicodeString(&uniDriverName, wzDriverName);
	Status = ObReferenceObjectByName(&uniDriverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&DriverObject);
	if (NT_SUCCESS(Status))
	{
		for (PDEVICE_OBJECT TravelDeviceObject = DriverObject->DeviceObject;
			TravelDeviceObject != NULL;
			TravelDeviceObject = TravelDeviceObject->NextDevice)		// 遍历设备链
		{
			if ((UINT_PTR)TravelDeviceObject->AttachedDevice == DeviceObject)	
			{
				TravelDeviceObject->AttachedDevice = ((PDEVICE_OBJECT)DeviceObject)->AttachedDevice;	 // 移除
			}

		}
		ObDereferenceObject(DriverObject);
	}

	return Status;
}


NTSTATUS
RemoveFilterDriver(IN PFILTER_DRIVER_ENTRY_INFORMATION FilterDriverEntry)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	switch (FilterDriverEntry->Type)
	{
	case Disk:
	{
		Status = ClearFilters(L"\\Driver\\Disk", FilterDriverEntry->FilterDeviceObject);

	}
	default:
		break;
	}
	return Status;
}
