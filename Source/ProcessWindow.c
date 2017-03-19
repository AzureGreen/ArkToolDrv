#include "ProcessWindow.h"

// W32KAPI
typedef
HANDLE ( * pfnNtUserQueryWindow)(
	IN HWND hwnd,
	IN UINT_PTR WindowInfo);

// W32KAPI
typedef 
NTSTATUS ( * pfnNtUserBuildHwndList)(
	IN HDESK hdesk,
	IN HWND hwndNext,
	IN BOOL fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT PUINT pcHwndNeeded);

extern DYNAMIC_DATA g_DynamicData;

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

	UINT32   NumberOfWnds = (OutputLength - sizeof(PROCESS_WINDOW_INFORMATION)) / sizeof(PROCESS_WINDOW_ENTRY_INFORMATION);

	// ���sssdt���к�����ַ

	if (ProcessId && pwi)
	{
		pfnNtUserQueryWindow NtUserQueryWindow = (pfnNtUserQueryWindow)GetSSSDTFunctionAddress(g_DynamicData.NtUserQueryWindowIndex);
		pfnNtUserBuildHwndList NtUserBuildHwndList = (pfnNtUserBuildHwndList)GetSSSDTFunctionAddress(g_DynamicData.NtUserBuildHwndListIndex);
		if (NtUserQueryWindow && NtUserBuildHwndList)
		{
		/*	Status = NtUserBuildHwndList(NULL, NULL, FALSE, 0, NumberOfWnds, (HWND*)((ULONG)pwi + sizeof(UINT32)),
				&pwi->NumberOfWnds);  */

			Status = NtUserBuildHwndList(NULL, NULL, FALSE, 0, NumberOfWnds, (HWND*)(pwi->Wnds), &pwi->NumberOfWnds);
			if (NT_SUCCESS(Status))
			{
				UINT32 Count = pwi->NumberOfWnds;
				ULONG i = 0;
				HWND* WndBuffer = (HWND*)ExAllocatePool(NonPagedPool, sizeof(HWND) * Count);
				if (WndBuffer)
				{
				//	memcpy(WndBuffer, (PVOID)((ULONG)pwi + sizeof(UINT32)), sizeof(HWND) * Count);

					for (i = 0; i < Count; i++)
					{
						UINT32 ThreadId = 0, ProcessId = 0;
						HWND hWnd = WndBuffer[i];

						ProcessId = NtUserQueryWindow(hWnd, 0);

						ThreadId = NtUserQueryWindow(hWnd, 2);

						pwi->Wnds[i].hWnd = hWnd;
						pwi->Wnds[i].ProcessId = ProcessId;
						pwi->Wnds[i].ThreadId = ThreadId;
					}
					ExFreePool(WndBuffer);
				}
			}
		}
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
	}
	
	return Status;
}

