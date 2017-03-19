#ifndef CXX_ProcessWindow_H
#define CXX_ProcessWindow_H

#include <ntifs.h>
#include <windef.h>		// HWND
#include "Private.h"
#include "KrnlSSSDT.h"

typedef struct _PROCESS_WINDOW_ENTRY_INFORMATION
{
	HWND   hWnd;
	UINT32 ProcessId;
	UINT32 ThreadId;
} PROCESS_WINDOW_ENTRY_INFORMATION, *PPROCESS_WINDOW_ENTRY_INFORMATION;

typedef struct _PROCESS_WINDOW_INFORMATION
{
	UINT32                            NumberOfWnds;
	PROCESS_WINDOW_ENTRY_INFORMATION  Wnds[1];
} PROCESS_WINDOW_INFORMATION, *PPROCESS_WINDOW_INFORMATION;

NTSTATUS
EnumProcessWindow(IN UINT32 ProcessId, OUT PPROCESS_WINDOW_INFORMATION pwi, IN UINT32 OutputLength);

#endif // !CXX_ProcessWindow_H
