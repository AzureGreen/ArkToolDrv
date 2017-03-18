#ifndef CXX_KrnlSSSDT_H
#define CXX_KrnlSSSDT_H

#include <ntifs.h>

#include "Private.h"


BOOLEAN
GetKeServiceDescriptorTableShadow(OUT PUINT_PTR SSSDTAddress);

UINT_PTR
GetSSSDTFunctionAddress(IN UINT32 FunctionIndex);

#endif // !CXX_KrnlSSSDT_H
