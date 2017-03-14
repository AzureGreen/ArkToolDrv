#ifndef CXX_SysFilterDriver_H
#define CXX_SysFilterDriver_H

#include <ntifs.h>
#include "Private.h"
#include "Imports.h"
#include "NtStructs.h"


typedef enum _FILTER_TYPE
{
	Unkonw,
	File,				// 文件------------
	Disk,               // 磁盘    文件相关
	Volume,		        // 卷  ------------- 
	Keyboard,           // 键盘
	Mouse,				// 鼠标            硬件接口
	I8042prt,			// 键盘驱动
	Tcpip,				// tcpip-------------------
	NDIS,				// 网络驱动接口
	PnpManager,         // 即插即用管理器       网络相关
	Tdx,				// 网络相关
	Raw
} FILTER_TYPE;

typedef struct _FILTER_DRIVER_ENTRY_INFORMATION
{
	FILTER_TYPE Type;
	UINT_PTR    FilterDeviceObject;
	WCHAR       wzFilterDriverName[MAX_PATH];
	WCHAR       wzAttachedDriverName[MAX_PATH];
	WCHAR       wzFilePath[MAX_PATH];
} FILTER_DRIVER_ENTRY_INFORMATION, *PFILTER_DRIVER_ENTRY_INFORMATION;

typedef struct _FILTER_DRIVER_INFORMATION
{
	UINT32                          NumberOfFilterDrivers;
	FILTER_DRIVER_ENTRY_INFORMATION FilterDrivers[1];
} FILTER_DRIVER_INFORMATION, *PFILTER_DRIVER_INFORMATION;


NTSTATUS
FillFilterDriverInfo(IN PDEVICE_OBJECT AttachDeviceObject, IN PDRIVER_OBJECT AttachedDriverObject, OUT PFILTER_DRIVER_INFORMATION fdi, IN UINT32 NumberOfFilterDrivers, IN FILTER_TYPE Type);

NTSTATUS
GetFilterDriverByDriverName(IN WCHAR *wzDriverName, IN  PFILTER_DRIVER_INFORMATION fdi, IN UINT32 NumberOfFilterDrivers, IN FILTER_TYPE Type);

NTSTATUS
EnumFilterDriver(OUT PVOID OutputBuffer, IN UINT32 OutputLength);

NTSTATUS
ClearFilters(IN WCHAR *wzDriverName, IN UINT_PTR DeviceObject);

NTSTATUS
RemoveFilterDriver(IN PFILTER_DRIVER_ENTRY_INFORMATION FilterDriverEntry);

#endif // !CXX_SysFilterDriver_H
