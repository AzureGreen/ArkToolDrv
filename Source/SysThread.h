#ifndef CXX_SysThread_H
#define CXX_SysThread_H

#include <ntifs.h>

#include "Private.h"
#include "ProcessThread.h"



UINT_PTR
GetPspCidTableAddress();

VOID
EnumGradeOneHandleTable(IN UINT_PTR TableCode, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION pti, IN UINT32 NumberOfThreads);

VOID
EnumGradeTwoHandleTable(IN UINT_PTR TableCode, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION pti, IN UINT32 NumberOfThreads);


VOID
EnumGradeThreeHandleTable(IN UINT_PTR TableCode, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION pti, IN UINT32 NumberOfThreads);

NTSTATUS
EnumSystemThread(OUT PVOID OutputBuffer, IN UINT32 OutputLength);

#endif // !CXX_SysThread_H
