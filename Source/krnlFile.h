#ifndef CXX_KrnlFile_H
#define CXX_KrnlFile_H

#include <ntifs.h>
#include <stdlib.h>
#include <ntimage.h>
#include "Private.h"
#include "NtStructs.h"
#include "Imports.h"

#define MAX_NAME 60

#define MakePtr(a, b, c) ((a)((PUINT8)b + c))

typedef enum _ePhKrnlFileColumn
{
	PH_KRNLFILE_NTOSKRNL_IAT,
	PH_KRNLFILE_NTOSKRNL_EAT,
	PH_KRNLFILE_WIN32K_IAT,
	PH_KRNLFILE_WIN32K_EAT,
	PH_KRNLFILE_HALDLL_IAT,
	PH_KRNLFILE_HALDLL_EAT
} ePhKrnlFileColumn;


typedef struct  _FILE_INFORMATION
{
	char     szFileFullPath[MAX_PATH];
	char     *szFileData;
	PVOID    BaseAddress;
	UINT_PTR Size;
} FILE_INFORMATION, *PFILE_INFORMATION;

typedef struct _IAT_ENTRY_INFORMATION
{
	UINT_PTR CurFuncAddress;
	UINT_PTR OriFuncAddress;
	CHAR     szFunctionName[MAX_NAME];
	CHAR     szModuleName[MAX_NAME];
} IAT_ENTRY_INFORMATION, *PIAT_ENTRY_INFORMATION;

typedef struct _IAT_INFORMATION
{
	UINT32                 NumberOfImportFunctions;
	IAT_ENTRY_INFORMATION  ImportFunction[1];
} IAT_INFORMATION, *PIAT_INFORMATION;

typedef struct _EAT_ENTRY_INFORMATION
{
	UINT_PTR CurFuncAddress;
	UINT_PTR OriFuncAddress;
	CHAR     szFunctionName[MAX_NAME];
} EAT_ENTRY_INFORMATION, *PEAT_ENTRY_INFORMATION;

typedef struct _EAT_INFORMATION
{
	UINT32                 NumberOfExportFunctions;
	EAT_ENTRY_INFORMATION  ExportFunction[1];
} EAT_INFORMATION, *PEAT_INFORMATION;

BOOLEAN
GetKrnlFileModuleInfo(OUT PUINT_PTR KernelBase, OUT PUINT32 KernelSize, IN CHAR* szModuleFileFullName, IN CHAR* szModuleFile);

BOOLEAN
ReadFileInfo(IN PFILE_INFORMATION FileInfo);

PIMAGE_SECTION_HEADER
GetSectionHeaderFromRva(IN UINT32 RVA, IN PIMAGE_NT_HEADERS NtHeader);

PVOID
GetDirectoryAddress(IN PUINT8 AddressBase, IN UINT16 DirectoryIndex, IN PUINT32 Size, IN PINT_PTR Diff, IN BOOLEAN IsFile);

BOOLEAN
GetModuleInfo(IN CHAR* szModuleName,/* OUT CHAR* szFileFullPath,*/ OUT PRTL_PROCESS_MODULE_INFORMATION pmi);

PFILE_INFORMATION
CreateFileData(IN PRTL_PROCESS_MODULE_INFORMATION ModuleInfo, IN CHAR* szModuleName);

BOOLEAN
GetExportFunctionAddress(IN PUINT8 BaseAddress, IN CHAR* szFunctionName, OUT PUINT_PTR ExportFunctionAddress, IN BOOLEAN IsFile);

NTSTATUS
EnumIATTable(OUT PIAT_INFORMATION OutBuffer, IN UINT32 OutputLength);

NTSTATUS
QueryKrnlFileIATFunction(OUT PVOID OutputBuffer, IN UINT32 OutputLength, IN CHAR* szModuleFile);

NTSTATUS
EnumEATTable(PVOID  KernelBase, OUT PEAT_INFORMATION OutBuffer, IN UINT32 OutputLength, IN CHAR* szModuleFile);

NTSTATUS
QueryKrnlFileEATFunction(OUT PVOID OutputBuffer, IN UINT32 OutputLength, IN CHAR* szModuleFile);

NTSTATUS
EnumKrnlFileFunctions(IN INT iKrnlFile, OUT PVOID OutputBuffer, IN UINT32 OutputLength);

#endif // !CXX_KrnlFile_H
