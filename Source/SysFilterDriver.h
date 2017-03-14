#ifndef CXX_SysFilterDriver_H
#define CXX_SysFilterDriver_H

#include <ntifs.h>
#include "Private.h"
#include "Imports.h"
#include "NtStructs.h"


typedef enum _FILTER_TYPE
{
	Unkonw,
	File,				// �ļ�------------
	Disk,               // ����    �ļ����
	Volume,		        // ��  ------------- 
	Keyboard,           // ����
	Mouse,				// ���            Ӳ���ӿ�
	I8042prt,			// ��������
	Tcpip,				// tcpip-------------------
	NDIS,				// ���������ӿ�
	PnpManager,         // ���弴�ù�����       �������
	Tdx,				// �������
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
