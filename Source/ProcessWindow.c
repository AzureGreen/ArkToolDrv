#include "ProcessWindow.h"




/************************************************************************
*  Name : EnumProcessWindow
*  Param: ProcessId				����Id				 ��IN��
*  Param: pwi					Ring3����Ҫ���ڴ���Ϣ��OUT��
*  Param: OutputLength			Ring3�㴫�ݵķ������ȣ�IN��
*  Ret  : NTSTATUS
*  ö��Ŀ����̵ľ����Ϣ������Ring3�ṩ�ṹ��
************************************************************************/

NTSTATUS
EnumProcessWindow(IN UINT32 ProcessId, OUT PPROCESS_WINDOW_INFORMATION pwi, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	// ���sssdt���к�����ַ

	if (!ProcessId ||
		!pwi)
	{
		return STATUS_INVALID_PARAMETER;
	}

	

	return Status;
}

