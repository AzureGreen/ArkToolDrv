#include "Dispatches.h"


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