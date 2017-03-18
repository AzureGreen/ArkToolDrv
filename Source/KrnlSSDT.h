#ifndef CXX_KrnlSSDT_H
#define CXX_KrnlSSDT_H

#include <ntifs.h>
#include "NtStructs.h"

typedef struct _SSDT_FUNCTION_INFORMATION
{
	UINT32	    Index;
	UINT_PTR	CurrentAddress;
	UINT_PTR	OriginalAddress;
	CHAR	    szFunctionName[80];
} SSDT_FUNCTION_INFORMATION, *PSSDT_FUNCTION_INFORMATION;

BOOLEAN
GetKeServiceDescriptorTable(OUT PUINT_PTR SSDTAddress);

UINT_PTR
GetSSDTFunctionAddress(IN UINT32 FunctionIndex);

VOID
WPOFF();

VOID
WPON();

NTSTATUS
ResumeSSDTHook(IN UINT32 FunctionIndex, IN UINT_PTR OriginalAddress);

#endif // !CXX_KrnlSSDT_H
