/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include <ntifs.h>

#ifndef CXX_PCHunterDrv_H
#define CXX_PCHunterDrv_H

#define DEVICE_NAME  L"\\Device\\PCHunterDrvDeviceName"
#define LINK_NAME    L"\\??\\PCHunterDrvLinkName"


VOID
	UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS
	DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif