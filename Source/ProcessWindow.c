#include "ProcessWindow.h"




/************************************************************************
*  Name : EnumProcessWindow
*  Param: ProcessId				进程Id				 （IN）
*  Param: pwi					Ring3层需要的内存信息（OUT）
*  Param: OutputLength			Ring3层传递的返出长度（IN）
*  Ret  : NTSTATUS
*  枚举目标进程的句柄信息，存入Ring3提供结构体
************************************************************************/

NTSTATUS
EnumProcessWindow(IN UINT32 ProcessId, OUT PPROCESS_WINDOW_INFORMATION pwi, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// 获得sssdt表中函数地址

	if (!ProcessId ||
		!pwi)
	{
		return STATUS_INVALID_PARAMETER;
	}

	

	return Status;
}

