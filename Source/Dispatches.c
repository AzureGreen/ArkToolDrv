#include "Dispatches.h"

extern UINT_PTR  g_ServiceTableBase;

NTSTATUS
IoControlPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PVOID				InputBuffer = NULL;
	PVOID               OutputBuffer = NULL;
	UINT32				InputBufferLength = 0;
	UINT32				OutputBufferLength = 0;
	PIO_STACK_LOCATION	IrpStack;
	UINT32				IoControlCode;

	IrpStack = IoGetCurrentIrpStackLocation(Irp);		// 获得当前Irp堆栈
	InputBuffer = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
	OutputBuffer = Irp->UserBuffer;
	InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	switch (IrpStack->MajorFunction)
	{
	case IRP_MJ_DEVICE_CONTROL:
	{
		IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
		switch (IoControlCode)
		{
		//////////////////////////////////////////////////////////////////////////
		// ProcessCore
		case IOCTL_PROC_SEND_SELF_PID:
		{
			DbgPrint("Send Self Pid\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT32));

					Status = SetSelfProcessId(*(PUINT32)InputBuffer, OutputBuffer, &OutputBufferLength);

					Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_GET_PROCESS_COUNT:
		{
			DbgPrint("Get Process Count\r\n");

			__try
			{
				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT32));

				Status = GetSystemProcessCount(OutputBuffer, &OutputBufferLength);

				Irp->IoStatus.Information = OutputBufferLength;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}

			break;
		}
		case IOCTL_PROC_ENUM_PROCESS_LIST:
		{
			DbgPrint("Enum Process List\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = EnumSystemProcessList(*(PUINT32)InputBuffer, OutputBuffer, &OutputBufferLength);

					Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PROCESS_THREAD:
		{
			DbgPrint("Process Thread\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = EnumProcessThread(*(PUINT32)InputBuffer, OutputBuffer, OutputBufferLength);

					//Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PROCESS_MODULE:
		{
			DbgPrint("Process Module\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = EnumProcessModule(*(PUINT32)InputBuffer, OutputBuffer, OutputBufferLength);

					//Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PROCESS_PRIVILEGE:
		{
			DbgPrint("Process Privilege\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = EnumProcessPrivilege(*(PUINT32)InputBuffer, OutputBuffer, OutputBufferLength);

					//Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PRIVILEGE_ADJUST:
		{
			DbgPrint("Privilege Adjust\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = AdjustProcessTokenPrivileges((PPRIVILEGE_DATA)InputBuffer, (int*)OutputBuffer);

					//Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PROCESS_HANDLE:
		{
			DbgPrint("Process Handle\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(PVOID));

					Status = EnumProcessHandle(*(PUINT32)InputBuffer, OutputBuffer, OutputBufferLength);

					Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PROCESS_WINDOW:
		{
			DbgPrint("Process Window\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(PVOID));

					Status = EnumProcessWindow(*(PUINT32)InputBuffer, OutputBuffer, OutputBufferLength);

					Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PROCESS_MEMORY:
		{
			DbgPrint("Process Memory\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(PVOID));

					Status = EnumProcessMemory(*(PUINT32)InputBuffer, OutputBuffer, OutputBufferLength);

					Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_PROC_PROCESS_KILL:
		{
			DbgPrint("Kill Process\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(INT32));

					Status = KillProcess(*(PUINT32)InputBuffer, OutputBuffer);

					Irp->IoStatus.Information = OutputBufferLength;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		//////////////////////////////////////////////////////////////////////////
		// ModuleCore
		case IOCTL_MODU_ENUM_MODULE_LIST:
		{
			DbgPrint("Enum Module\r\n");

			__try
			{
				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = EnumSystemModuleList(OutputBuffer, OutputBufferLength);

				Irp->IoStatus.Information = OutputBufferLength;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}

			break;
		}
		case IOCTL_MODU_UNLOAD_MODULE:
		{
			DbgPrint("Unload Module\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(PVOID));

					Status = UnloadDriverObject((PVOID)*(PUINT_PTR)InputBuffer, InputBufferLength);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
			break;
		}
		//////////////////////////////////////////////////////////////////////////
		// KernelSys
		case IOCTL_SYS_ENUM_CALLBACK_LIST:
		{
			DbgPrint("Enum Callbacks\r\n");
			__try
			{
				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = EnumSysCallbackNotify(OutputBuffer, OutputBufferLength);

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_SYS_REMOVE_CALLBACK_ITEM:
		{
			DbgPrint("Remove Callback\r\n");

			if (InputBufferLength >= sizeof(SYS_CALLBACK_ENTRY_INFORMATION) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));

					Status = RemoveCallbackNotify((PSYS_CALLBACK_ENTRY_INFORMATION)InputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
			break;
		}
		case IOCTL_SYS_ENUM_IOTIMER_LIST:
		{
			DbgPrint("Enum IoTimer\r\n");
			__try
			{
				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = EnumIoTimer(OutputBuffer, OutputBufferLength);

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_SYS_REMOVE_IOTIMER_ITEM:
		{
			DbgPrint("Remove IoTimer\r\n");

			if (InputBufferLength >= sizeof(UINT_PTR) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));

					Status = RemoveIoTimer((PLIST_ENTRY)*(PUINT_PTR)InputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
			break;
		}
		case IOCTL_SYS_RUNORSTOP_IOTIMER_ITEM:
		{
			DbgPrint("Run Or Stop IoTimer\r\n");

			if (InputBufferLength >= sizeof(OPERATION_ON_IO_TIMER_INFORMATION) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));

					Status = RunOrStopIoTimer((POPERATION_ON_IO_TIMER_INFORMATION)InputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
			break;
		}
		case IOCTL_SYS_ENUM_DPCTIMER_LIST:
		{
			DbgPrint("Enum DpcTimer\r\n");
			__try
			{
				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = EnumDpcTimer(OutputBuffer, OutputBufferLength);

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_SYS_REMOVE_DPCTIMER_ITEM:
		{
			DbgPrint("Remove DpcTimer\r\n");

			if (InputBufferLength >= sizeof(UINT_PTR) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));

					Status = RemoveDpcTimer(*(PUINT_PTR)InputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
			break;
		}
		case IOCTL_SYS_ENUM_SYSTEMTHREAD_LIST:
		{
			DbgPrint("Enum System Thread\r\n");
			__try
			{
				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = EnumSystemThread(OutputBuffer, OutputBufferLength);

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_SYS_ENUM_FILTERDRIVER_LIST:
		{
			DbgPrint("Enum Filter Driver\r\n");
			__try
			{
				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = EnumFilterDriver(OutputBuffer, OutputBufferLength);

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_SYS_REMOVE_FILTERDRIVER_ITEM:
		{
			DbgPrint("Remove Filter Driver\r\n");

			if (InputBufferLength >= sizeof(UINT_PTR) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));

					Status = RemoveFilterDriver(InputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
			break;
		}
		case IOCTL_KRNL_GET_KISERVICETABLE:
		{
			DbgPrint("Get SSDT\r\n");
			__try
			{
				PSYSTEM_SERVICE_DESCRIPTOR_TABLE SSDT = NULL;

				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = GetKeServiceDescriptorTable((PUINT_PTR)&SSDT);

				g_ServiceTableBase = (UINT_PTR)SSDT->ServiceTableBase;

				*(PUINT_PTR)OutputBuffer = g_ServiceTableBase;

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_KRNL_ENUM_SSDTFUNCTION_LIST:
		{
			DbgPrint("Enum SSDT Functions\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					*(PUINT_PTR)OutputBuffer = (UINT_PTR)GetSSDTFunctionAddress(*(PUINT32)InputBuffer);

					DbgPrint("SSDT Function Address: %p\r\n", *(PUINT_PTR)OutputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_KRNL_RESUME_HOOKED_SSDTFUNCTION:
		{
			DbgPrint("Resume SSDT Hook\r\n");

			if (InputBufferLength >= sizeof(SSDT_FUNCTION_INFORMATION) && InputBuffer)
			{
				__try
				{
					PSSDT_FUNCTION_INFORMATION SSDTInfo = NULL;

					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));

					SSDTInfo = (PSSDT_FUNCTION_INFORMATION)InputBuffer;

					Status = ResumeSSDTHook(SSDTInfo->Index, SSDTInfo->OriginalAddress);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
			break;
		}
		case IOCTL_KRNL_GET_WIN32KSERIVCE:
		{
			DbgPrint("Get Win32k Table\r\n");
			__try
			{
				PSYSTEM_SERVICE_DESCRIPTOR_TABLE SSSDT = NULL;

				ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

				Status = GetKeServiceDescriptorTableShadow((PUINT_PTR)&SSSDT);

				g_ServiceTableBase = (UINT_PTR)SSSDT->ServiceTableBase;

				*(PUINT_PTR)OutputBuffer = g_ServiceTableBase;

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = Status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Catch Exception\r\n");
				Status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case IOCTL_KRNL_ENUM_SSSDTFUNCTION_LIST:
		{
			DbgPrint("Enum SSSDT Functions\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					*(PUINT_PTR)OutputBuffer = (UINT_PTR)GetSSSDTFunctionAddress(*(PUINT32)InputBuffer);

					DbgPrint("SSDT Function Address: %p\r\n", *(PUINT_PTR)OutputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_KRNL_ENUM_KRNLFILE:
		{
			DbgPrint("Enum Functions\r\n");

			if (InputBufferLength >= sizeof(INT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(INT32));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = EnumKrnlFileFunctions(*(PINT)InputBuffer, OutputBuffer, OutputBufferLength);

					DbgPrint("SSDT Function Address: %p\r\n", *(PUINT_PTR)OutputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_KRNL_ENUM_KRNLIAT:
		{
			DbgPrint("Enum IAT\r\n");

			if (InputBufferLength > 0 && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = QueryKrnlFileIATFunction(OutputBuffer, OutputBufferLength, (CHAR*)InputBuffer);

					DbgPrint("SSDT Function Address: %p\r\n", *(PUINT_PTR)OutputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}
		case IOCTL_KRNL_ENUM_KRNLEAT:
		{
			DbgPrint("Enum EAT\r\n");

			if (InputBufferLength >= sizeof(UINT32) && InputBuffer)
			{
				__try
				{
					ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT8));
					ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(UINT8));

					Status = QueryKrnlFileEATFunction(OutputBuffer, OutputBufferLength, (CHAR*)InputBuffer);

					DbgPrint("SSDT Function Address: %p\r\n", *(PUINT_PTR)OutputBuffer);

					Irp->IoStatus.Information = 0;
					Irp->IoStatus.Status = Status;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Catch Exception\r\n");
					Status = STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}

			break;
		}

		default:
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			break;
		}
		break;
	}
	default:
		break;
	}

	Status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}