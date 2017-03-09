/****************************************************************************************
* Copyright (C) 2015
****************************************************************************************/
#include <ntifs.h>

#ifndef CXX_PCHunterDrv_H
#define CXX_PCHunterDrv_H

#define DEVICE_NAME  L"\\Device\\PCHunterDrvDeviceName"
#define LINK_NAME    L"\\??\\PCHunterDrvLinkName"

#include "Private.h"
#include "ProcessCore.h"
#include "ProcessThread.h"
#include "Dispatches.h"


NTSTATUS 
	InitDynamicData(IN OUT PDYNAMIC_DATA DynamicData);

NTSTATUS
	DefaultPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);

VOID
	UnloadDriver(PDRIVER_OBJECT DriverObject);

#endif