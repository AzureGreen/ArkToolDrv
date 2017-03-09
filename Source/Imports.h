#ifndef CXX_Imports_H
#define CXX_Imports_H

#include <ntifs.h>

NTKERNELAPI
PPEB
PsGetProcessPeb(
	__in PEPROCESS Process
);

#endif // !CXX_Imports_H
