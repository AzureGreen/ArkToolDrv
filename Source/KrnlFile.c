#include "krnlFile.h"

PFILE_INFORMATION    g_FileInfoPtr = NULL;
FILE_INFORMATION     g_FileInfo;
char                 g_szKrnlFileFullPath[MAX_PATH] = { 0 };
UINT_PTR             g_KrnlFileBase = 0;
UINT_PTR             g_KrnlFileSize = 0;

UINT32               g_ModuleInfoLength = 0;
PRTL_PROCESS_MODULES g_ModuleInfo = NULL;

// 通过模块名称 使用NtQuerySystemInformation获得模块的信息（基址 大小 路径）  已经加载在内存中的了
BOOLEAN	
GetKrnlFileModuleInfo(OUT PUINT_PTR KernelBase, OUT PUINT32 KernelSize, IN CHAR* szModuleFileFullName, IN CHAR* szModuleFile)
{
	NTSTATUS			 Status = STATUS_UNSUCCESSFUL;
	PRTL_PROCESS_MODULES ProcessModules = NULL;
	PVOID				 BufferData = NULL;
	UINT32				 BufferLength = 0;
	PETHREAD             EThread = NULL;
	UINT8                PreviousMode = 0;
	UINT32               i = 0;

	EThread = PsGetCurrentThread();
	PreviousMode = ChangeThreadMode(EThread, KernelMode);

	Status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &BufferLength);  //不能被Hook
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
	{
		DbgPrint("STATUS_INFO_LENGTH_MISMATCH FAILED\r\n");
		return FALSE;
	}

	BufferData = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, BufferLength);
	if (BufferData == NULL)
	{
		return FALSE;
	}

	Status = NtQuerySystemInformation(SystemModuleInformation, BufferData, BufferLength, &BufferLength);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("NtQuerySystemInformation Failed\r\n");
		ExFreePool(BufferData);
		return FALSE;
	}

	ProcessModules = (PRTL_PROCESS_MODULES)BufferData;

	for (i = 0; i < ProcessModules->NumberOfModules; i++)
	{
		if (_stricmp(szModuleFile, "ntoskrnl.exe") == 0)		// 这里只是用来判断下而已，所以没事，第一模块必定是Ntosxxxx.exe
		{
			i = 0;
			DbgPrint("Win32k ModuleId: %d\r\n", i);
			break;
		}
		else if (_stricmp(ProcessModules->Modules[i].FullPathName + ProcessModules->Modules[i].OffsetToFileName, szModuleFile) == 0)
		{
			DbgPrint("Win32k ModuleId: %d\r\n", i);
			break;
		}
	}

	DbgPrint("%s\r\n", ProcessModules->Modules[i].FullPathName);

	*KernelBase = (UINT_PTR)ProcessModules->Modules[i].ImageBase;
	*KernelSize = ProcessModules->Modules[i].ImageSize;

	if (memcmp(ProcessModules->Modules[i].FullPathName, "\\??\\", strlen("\\??\\")) == 0)
	{
		strcpy(szModuleFileFullName, ProcessModules->Modules[i].FullPathName);
	}
	else if (strnicmp(ProcessModules->Modules[i].FullPathName, "\\SystemRoot\\", strlen("\\SystemRoot\\")) == 0)
	{
		char* Temp = NULL;
		strcpy(szModuleFileFullName, "\\??\\C:\\Windows\\"); /*System32\\*/		// 这儿是不是有问题

		Temp = ProcessModules->Modules[i].FullPathName + strlen("\\SystemRoot\\");

		strcat(szModuleFileFullName, Temp);
	}
	else if (strnicmp(ProcessModules->Modules[i].FullPathName, "\\Windows\\", strlen("\\Windows\\")) == 0)
	{
		char* Temp = NULL;
		strcpy(szModuleFileFullName, "\\??\\C:\\");

		Temp = ProcessModules->Modules[i].FullPathName;

		strcat(szModuleFileFullName, Temp);
	}

	DbgPrint("szModuleFileFullName: %s\r\n", szModuleFileFullName);

	if (BufferData)
	{
		ExFreePool(BufferData);
	}
	
	ChangeThreadMode(EThread, PreviousMode);

	return TRUE;
}

// 读取文件到FileData里
BOOLEAN
ReadFileInfo(IN PFILE_INFORMATION FileInfo)
{
	BOOLEAN           bOk = FALSE;
	NTSTATUS          Status = STATUS_UNSUCCESSFUL;
	WCHAR             wzFileName[MAX_PATH] = { 0 };
	HANDLE            FileHandle = NULL;
	IO_STATUS_BLOCK   IoSb = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING    uniFileName = { 0 };
	
	mbstowcs(wzFileName, FileInfo->szFileFullPath, MAX_PATH);		// 单字转双字
	
	RtlInitUnicodeString(&uniFileName, wzFileName);
	InitializeObjectAttributes(&oa, &uniFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwCreateFile(&FileHandle,
		GENERIC_READ,
		&oa,
		&IoSb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(Status))
	{
		//获得文件信息

		FILE_STANDARD_INFORMATION   fsi;
		LARGE_INTEGER               ByteOffset = { 0,0 };

		Status = ZwQueryInformationFile(FileHandle, &IoSb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (NT_SUCCESS(Status))
		{
			if (fsi.AllocationSize.u.LowPart != 0)
			{
				FileInfo->szFileData = (char*)ExAllocatePool(PagedPool, fsi.AllocationSize.u.LowPart);
				if (FileInfo->szFileData)
				{
					//读取文件长度
					Status = ZwReadFile(FileHandle,
						NULL,
						NULL,
						NULL,
						&IoSb,
						FileInfo->szFileData,
						fsi.AllocationSize.u.LowPart,
						&ByteOffset,
						NULL);
					if (NT_SUCCESS(Status))
					{
						bOk = TRUE;
					}
					else
					{
						ExFreePool(FileInfo->szFileData);
						bOk = FALSE;
					}
				}
			}
			ZwClose(FileHandle);
		}
	}
	return bOk;
}

// 判断RVA是在哪个节表当中
PIMAGE_SECTION_HEADER
GetSectionHeaderFromRva(IN UINT32 RVA, IN PIMAGE_NT_HEADERS NtHeader)  
{
	PIMAGE_SECTION_HEADER  SectionHeader = IMAGE_FIRST_SECTION(NtHeader);	

	for (INT i = 0; i < NtHeader->FileHeader.NumberOfSections; i++, SectionHeader++)
	{

		if ((RVA >= SectionHeader->VirtualAddress) &&
			(RVA < (SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize)))
		{
			return SectionHeader;
		}
	}
	return NULL;
}

// 通过模块基地址，获得想要的表的地址
// AddressBase            基地址 
// DirectoryIndex         表目录
// Size                   表大小
// Diff                   文件格式与内存格式的偏移
// IsFile                 true 文件格式 false 内存格式

PVOID
GetDirectoryAddress(IN PUINT8 BaseAddress, IN UINT16 DirectoryIndex, IN PUINT32 Size, IN PINT_PTR Diff, IN BOOLEAN IsFile)
{
	PIMAGE_DOS_HEADER      DosHeader = NULL;
	PIMAGE_NT_HEADERS      NtHeader = NULL;
	PIMAGE_SECTION_HEADER  SectionHeader = NULL;
	PVOID			       DirectoryAddress = NULL;

	DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	if (MmIsAddressValid(DosHeader) && DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		NtHeader = MakePtr(PIMAGE_NT_HEADERS, DosHeader, DosHeader->e_lfanew);
		if (MmIsAddressValid(NtHeader) && NtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			// 这里判断是文件映射 还是将文件读入到内存的形式
			if (IsFile)  
			{
				// 判断导入表属于哪个节表中
				SectionHeader = GetSectionHeaderFromRva(NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].VirtualAddress, NtHeader);
				if (SectionHeader == NULL)
				{
					return NULL;
				}

				//  PointerToRawData == 0x200       VirtualAddress == 0x1000    
				//                                              RVA = 0x1030
				//	那么导出表在文件中的偏移就是0x230  返回	
				//  节在内存中的RVA - 在文件中节的偏移 = 该节被提高了多少   
				//  0x1000 - 0x200 = 0xE00	     
				*Diff = (INT)(SectionHeader->VirtualAddress - SectionHeader->PointerToRawData);
			}
			else
			{
				*Diff = 0;
			}

			DirectoryAddress = MakePtr(PVOID, DosHeader, NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].VirtualAddress - *Diff);
			if (DirectoryAddress == (PVOID)NtHeader)
			{
				return NULL;
			}

			if (Size)
			{
				//*Size = MakePtr(UINT32, DosHeader, NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].Size);
				//*Size -= (UINT_PTR)DosHeader;
				*Size = NtHeader->OptionalHeader.DataDirectory[DirectoryIndex].Size;
			}
			return DirectoryAddress;
		}
	}

	return NULL;
}

// 通过模块名称获得模块完整路径 基地址等信息
BOOLEAN
GetModuleInfo(IN CHAR* szModuleName,/* OUT CHAR* szFileFullPath,*/ OUT PRTL_PROCESS_MODULE_INFORMATION pmi)
{	
	BOOLEAN   bOk = FALSE;
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;
	UINT32    ReturnLength = 0;
	PETHREAD  EThread = NULL;
	UINT8     PreviousMode = 0;

	EThread = PsGetCurrentThread();
	PreviousMode = ChangeThreadMode(EThread, KernelMode);

	Status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &ReturnLength);

	if (g_ModuleInfoLength != ReturnLength && g_ModuleInfoLength > 0)	// 如果大小有变，则清空缓冲区
	{
		ExFreePool(g_ModuleInfo);
		g_ModuleInfo = NULL;
		g_ModuleInfoLength = ReturnLength;	// 更新大小全局变量
	}

	if (g_ModuleInfo == NULL)
	{
		g_ModuleInfo = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, ReturnLength);
	}

	if (g_ModuleInfo)
	{
		Status = NtQuerySystemInformation(SystemModuleInformation, g_ModuleInfo, ReturnLength, &ReturnLength);
		if (NT_SUCCESS(Status))
		{
			UINT32 KrnlModuleCount = 0;
			CHAR   szKrnlModuleName[MAX_NAME] = { 0 };
			
			PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = NULL;

			KrnlModuleCount = g_ModuleInfo->NumberOfModules;
			ModuleInfo = g_ModuleInfo->Modules;

			strcpy(szKrnlModuleName, ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName);		// 第一模块 

			for (INT i = 0; i < KrnlModuleCount; i++)
			{
				if (_stricmp(szModuleName, ModuleInfo[i].FullPathName + ModuleInfo[i].OffsetToFileName) == 0 ||
					(_stricmp(szModuleName, "ntoskrnl.exe") == 0 &&    // 还是感觉这里写死不太好，毕竟 szModuleName 是导入表里的模块名称
						_stricmp(szKrnlModuleName, ModuleInfo[i].FullPathName + ModuleInfo[i].OffsetToFileName) == 0))
				{
					pmi->ImageBase = ModuleInfo[i].ImageBase;
					pmi->ImageSize = ModuleInfo[i].ImageSize;

					if (strstr(ModuleInfo[i].FullPathName, "SystemRoot") == NULL)	// find first
					{
						strcpy(pmi->FullPathName, ModuleInfo[i].FullPathName);
					//	strcpy(szFileFullPath, ModuleInfo[i].FullPathName);
					}
					else
					{
						strcpy(pmi->FullPathName, "\\??\\C:");
						strcat(pmi->FullPathName, ModuleInfo[i].FullPathName);

					//	strcpy(szFileFullPath, "\\??\\C:");
					//	strcat(szFileFullPath, ModuleInfo[i].FullPathName);
					}

					if (strnicmp(ModuleInfo[i].FullPathName, "\\Windows\\", strlen("\\Windows\\")) == 0)
					{
						strcpy(pmi->FullPathName, "\\??\\C:");
						strcat(pmi->FullPathName, ModuleInfo[i].FullPathName);
						/*strcpy(szFileFullPath, "\\??\\C:\\");
						strcat(szFileFullPath, (CHAR*)ModuleInfo[i].FullPathName);*/
					}
					else
					{
						strcpy(pmi->FullPathName, ModuleInfo[i].FullPathName);
					//	strcpy(szFileFullPath, ModuleInfo[i].FullPathName);
					}

					bOk = TRUE;
					break;
				}
			}

		}
	}

	ChangeThreadMode(EThread, PreviousMode);

	return bOk;
}


// 如果传入了结构体 则用结构体填充FileInfo相关信息 
// 如果没传结构体 传入的模块名称，则先通过模块名称完成结构体，再去填充FileInfo相关信息
PFILE_INFORMATION
CreateFileData(IN PRTL_PROCESS_MODULE_INFORMATION ModuleInfo, IN CHAR* szModuleName)
{
	BOOLEAN        bOk = FALSE;
//	CHAR           szFullName[MAX_PATH] = { 0 };

	RTL_PROCESS_MODULE_INFORMATION  ModuleEntry = { 0 };

	if (!ModuleInfo)  // 通过文件名称获得文件全路径
	{
		bOk = GetModuleInfo(szModuleName/*, szFullName*/, &ModuleEntry);		// 通过模块名称获得模块信息
		if (bOk)
		{
			DbgPrint("Get Module Info Succ\r\n");
		}
		else
		{
			return NULL;
		}
	}

	if (g_FileInfoPtr == NULL)
	{
		g_FileInfoPtr = (PFILE_INFORMATION)ExAllocatePool(PagedPool, sizeof(FILE_INFORMATION));
	}

	if (g_FileInfoPtr)
	{
		RtlZeroMemory(g_FileInfoPtr, sizeof(FILE_INFORMATION));

		if (ModuleInfo)
		{
			g_FileInfoPtr->BaseAddress = ModuleInfo->ImageBase;
			g_FileInfoPtr->Size = ModuleInfo->ImageSize;
			strcpy(g_FileInfoPtr->szFileFullPath, ModuleInfo->FullPathName);
		}
		else    // 刚查找信息了的
		{
			g_FileInfoPtr->BaseAddress = (PVOID)ModuleEntry.ImageBase;
			g_FileInfoPtr->Size = ModuleEntry.ImageSize;
			memcpy(g_FileInfoPtr->szFileFullPath, ModuleEntry.FullPathName, strlen(ModuleEntry.FullPathName) + 1);

		}

		bOk = ReadFileInfo(g_FileInfoPtr);
		if (bOk)
		{
			return g_FileInfoPtr;
		}
	}

	return NULL;
}


// 通过函数名称在导出表中查地址(注意：！！！这里返回出去的实际是 偏移 相对于内存加载基地址的偏移！！！，用于后面对齐用)
BOOLEAN 
GetExportFunctionAddress(IN PUINT8 BaseAddress, IN CHAR* szFunctionName, OUT PUINT_PTR ExportFunctionAddress, IN BOOLEAN IsFile)
{
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	INT_PTR	                ExportDiff = 0;
	
	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)GetDirectoryAddress(BaseAddress, IMAGE_DIRECTORY_ENTRY_EXPORT, NULL, &ExportDiff, IsFile);
	if (ExportDirectory)
	{
		PUINT32	  AddressOfNames = MakePtr(PUINT32, BaseAddress, ExportDirectory->AddressOfNames - ExportDiff);               // 函数名称表
		PUINT32   AddressOfFunctions = MakePtr(PUINT32, BaseAddress, ExportDirectory->AddressOfFunctions - ExportDiff);       // 函数地址表
		PUINT16	  AddressOfNameOrdinals = MakePtr(PUINT16, BaseAddress, ExportDirectory->AddressOfFunctions - ExportDiff);    // 函数名称序号表

		for (int i = 0; i < ExportDirectory->NumberOfNames; i++)
		{
			if (_stricmp(szFunctionName, (CHAR*)((PUINT8)BaseAddress + AddressOfNames[i] - ExportDiff)) == 0)
			{
				//*ExportFunctionAddress = (UINT_PTR)((PUINT8)BaseAddress + AddressOfFunctions[AddressOfNameOrdinals[i]]);      // 肯定是要加基地址的！
				*ExportFunctionAddress = AddressOfFunctions[AddressOfNameOrdinals[i]];
				return TRUE;
			}
		}
	}

	return FALSE;
}


NTSTATUS
EnumIATTable(OUT PIAT_INFORMATION OutBuffer, IN UINT32 OutputLength)
{

	NTSTATUS						 Status = STATUS_UNSUCCESSFUL;

	PIMAGE_IMPORT_DESCRIPTOR	     ImportDescriptor = NULL;		// 导入表地址（文件）
	UINT32                           ImportSize = 0;				// 导入表大小（文件）
	INT32                            ImportDiff = 0;               // 导入表文件与内存差值

	PIMAGE_THUNK_DATA				 ImportFirstThunk = NULL;       // IAT地址 内存
	INT32                            IATDiff = 0;                   // IAT文件 内存 差值
	UINT32                           IATSize = 0;                   // IAT大小 内存

	UINT32						     ImportDescriptorIndex = 0;    // 导入表索引 哪一张导入表
	PIMAGE_IMPORT_DESCRIPTOR		 ImportDescriptorArray[64] = { NULL }; // 保存每张导入表首地址数组
	UINT32                           MaxImportDescriptorCount = 0;         // 导入表个数

	CHAR*                            ImportModuleName = NULL;             // 导入模块名称

	PIMAGE_THUNK_DATA                ImportOriginalFirstThunk = NULL;     // 指向导入函数名称表
	PIMAGE_IMPORT_BY_NAME            OriginalName = NULL;                  // 导入函数名称
	UINT_PTR                         OriginalFunctionAddress = 0;          // 导入函数地址

	CHAR                             szIATOriginalImageFile[MAX_NAME] = { 0 };  

	PFILE_INFORMATION                ModuleFile = NULL;                    // 存有当前在枚举的模块的信息，每次循环会更新

	UINT32                           NumberOfImportFunctions = (OutputLength - sizeof(IAT_INFORMATION)) / sizeof(IAT_ENTRY_INFORMATION);

	if (g_FileInfo.BaseAddress != 0)
	{
		ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)GetDirectoryAddress((PUINT8)g_FileInfo.szFileData,
			IMAGE_DIRECTORY_ENTRY_IMPORT, &ImportSize, &ImportDiff, TRUE);	 // 文件内容

		ImportFirstThunk = (PIMAGE_THUNK_DATA)GetDirectoryAddress((PUINT8)g_FileInfo.BaseAddress,
			IMAGE_DIRECTORY_ENTRY_IAT, &IATSize, &IATDiff, FALSE);			// 内存内容 IAT

		if (IATSize / sizeof(UINT32) > NumberOfImportFunctions)
		{
			OutBuffer->NumberOfImportFunctions = IATSize / sizeof(UINT32);		// Offset不会超过4字节

			Status = STATUS_BUFFER_TOO_SMALL;

			goto Exit;
		}

		if (!ImportFirstThunk || !ImportDescriptor)
		{
			Status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}

		while (ImportDescriptor->Name)  // 导入模块不为空  从自己的内存中获得所有的模块
		{
			ImportDescriptorArray[ImportDescriptorIndex] = ImportDescriptor;	// 保存在数组中

			ImportDescriptorIndex++;
			ImportDescriptor++;
		}

		if (ImportDescriptorIndex == 0)
		{
			Status = STATUS_UNSUCCESSFUL;
			goto Exit;  // 该模块没有任何的导入模块
		}

		MaxImportDescriptorCount = ImportDescriptorIndex;
		ImportDescriptorIndex = 0;
		ImportDescriptor = ImportDescriptorArray[ImportDescriptorIndex];
		ImportDescriptorIndex++;

		// 通过文件内容 导入模块名称
		ImportModuleName = MakePtr(CHAR*, g_FileInfo.szFileData, ImportDescriptor->Name - ImportDiff);  // 文件内容
		if (!ImportModuleName)
		{
			Status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}

		ImportOriginalFirstThunk = MakePtr(PIMAGE_THUNK_DATA, g_FileInfo.szFileData, ImportDescriptor->OriginalFirstThunk - ImportDiff);     // 文件内容  INT

		// 通过导入的模块名找到导入模块
		// 导入模块的函数名称  导入的模块名称 

		while (ImportOriginalFirstThunk && ImportModuleName && IATSize && ImportFirstThunk->u1.Function)
		{

			if (_stricmp(szIATOriginalImageFile, ImportModuleName) != 0)	// 第一次进
			{
				if (ModuleFile != NULL && ModuleFile->szFileData != NULL && MmIsAddressValid(ModuleFile->szFileData))
				{
					DbgPrint("ExFreePool(ModuleFile->szFileData)\r\n");
					ExFreePool(ModuleFile->szFileData);
				}
				ModuleFile = CreateFileData(NULL, ImportModuleName);
				if (ModuleFile == NULL)
				{
					DbgPrint("CreateFileData Failed\r\n");
					Status = STATUS_UNSUCCESSFUL;
					goto Exit;
				}

				RtlZeroMemory(szIATOriginalImageFile, MAX_NAME);
				strcpy(szIATOriginalImageFile, ImportModuleName);
			}

			strcpy(OutBuffer->ImportFunction[OutBuffer->NumberOfImportFunctions].szModuleName, ImportModuleName);

			OriginalName = MakePtr(PIMAGE_IMPORT_BY_NAME, g_FileInfo.szFileData, (UINT_PTR)ImportOriginalFirstThunk->u1.AddressOfData - ImportDiff);  // 通过Original(文件)获得函数名称

			// 从First(内存)中获得函数地址

			if (GetExportFunctionAddress((PUINT8)ModuleFile->szFileData, (CHAR*)OriginalName->Name, &OriginalFunctionAddress, TRUE))     // 从导入的模块中获得函数地址Offset
			{
				OriginalFunctionAddress += (UINT_PTR)ModuleFile->BaseAddress;		// Real Addr Get From Eat
				DbgPrint("ExportFuncAddr: %p\r\n", OriginalFunctionAddress);
			}


			strcpy(OutBuffer->ImportFunction[OutBuffer->NumberOfImportFunctions].szFunctionName, (CHAR*)OriginalName->Name);
			OutBuffer->ImportFunction[OutBuffer->NumberOfImportFunctions].CurFuncAddress = ImportFirstThunk->u1.Function;       // Get From IAT
			OutBuffer->ImportFunction[OutBuffer->NumberOfImportFunctions].OriFuncAddress = OriginalFunctionAddress;

			OutBuffer->NumberOfImportFunctions++;
			ImportFirstThunk++;
			ImportOriginalFirstThunk++;
			IATSize -= sizeof(UINT32);
			
			if (IATSize == 0)
			{
				break;
			}

			if (ImportFirstThunk->u1.Function == 0)  // 一个导入模块已经遍历完成
			{
				ImportFirstThunk++;
				IATSize -= sizeof(UINT32);

				ImportDescriptor = ImportDescriptorArray[ImportDescriptorIndex];  // 从数组中获得下一个导出模块

				if (ImportDescriptorIndex == MaxImportDescriptorCount)
				{
					break;
				}

				ImportDescriptorIndex++;

				ImportModuleName = MakePtr(CHAR*, g_FileInfo.szFileData, ImportDescriptor->Name - ImportDiff);    // 更新模块名称
				ImportOriginalFirstThunk = MakePtr(PIMAGE_THUNK_DATA, g_FileInfo.szFileData, ImportDescriptor->OriginalFirstThunk - ImportDiff);  // 文件内容  下一个INT

				if (ImportOriginalFirstThunk == NULL ||
					ImportModuleName == NULL ||
					(PUINT32)ImportFirstThunk->u1.Function == NULL ||
					IATSize == 0)
				{
					break;
				}
			}
		}
	}

	Status = STATUS_SUCCESS;

Exit:

	if (ModuleFile != NULL && ModuleFile->szFileData != NULL && MmIsAddressValid(ModuleFile->szFileData))
	{
		DbgPrint("ExFreePool(ModuleFile->szFileData)\r\n");
		ExFreePool(ModuleFile->szFileData);
	}

	return Status;
}


NTSTATUS 
QueryKrnlFileIATFunction(OUT PVOID OutputBuffer, IN UINT32 OutputLength, IN CHAR* szModuleFile)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DbgPrint("GetModuleInforNtoskrnl now:::\r\n");

	if (GetKrnlFileModuleInfo(&g_KrnlFileBase, &g_KrnlFileSize, g_szKrnlFileFullPath, szModuleFile))
	{
		DbgPrint("GetModuleInforNtoskrnl Success\r\n");
	}

	// 填充 FileData Base Size FullPath Data
	g_FileInfo.BaseAddress = (PVOID)g_KrnlFileBase;
	g_FileInfo.Size = g_KrnlFileSize;

	strcpy(g_FileInfo.szFileFullPath, g_szKrnlFileFullPath);
	ReadFileInfo(&g_FileInfo);		// 填充FileData

	Status = EnumIATTable((PIAT_INFORMATION)OutputBuffer, OutputLength);

	if (g_FileInfo.szFileData != NULL)
	{
		ExFreePool(g_FileInfo.szFileData);
	}

	return Status;
}

NTSTATUS 
EnumEATTable(PVOID  KernelBase, OUT PEAT_INFORMATION OutBuffer, IN UINT32 OutputLength, IN CHAR* szModuleFile)
{
	

	PIMAGE_DOS_HEADER       DosHeader = NULL;
	PIMAGE_NT_HEADERS       NtHeader = NULL;
//	IMAGE_OPTIONAL_HEADER   OptionalHeader = { 0 };
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

	UINT32         Base = 0;

	PFILE_INFORMATION ModuleInfo = NULL;

	UINT32          NumberOfExportFunctions = (OutputLength - sizeof(EAT_INFORMATION)) / sizeof(EAT_ENTRY_INFORMATION);

	DosHeader = (PIMAGE_DOS_HEADER)KernelBase;
	if (MmIsAddressValid(DosHeader) && DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		NtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHeader + DosHeader->e_lfanew);
		if (MmIsAddressValid(NtHeader) && NtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			ModuleInfo = CreateFileData(NULL, szModuleFile);
			if (ModuleInfo == NULL)
			{
				DbgPrint("CreateFileData Failed\r\n");
				return STATUS_UNSUCCESSFUL;
			}
			else
			{
				PUINT32  AddressOfFunctions;
				PUINT32  AddressOfNames;
				PUINT16  AddressOfNameOrdinals;

				ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)KernelBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // 获得导出表的RVA

				AddressOfFunctions = (ULONG*)((ULONG_PTR)DosHeader + ExportDirectory->AddressOfFunctions);
				AddressOfNames = (ULONG*)((ULONG_PTR)DosHeader + ExportDirectory->AddressOfNames);
				AddressOfNameOrdinals = (short*)((ULONG_PTR)DosHeader + ExportDirectory->AddressOfNameOrdinals);

				Base = ExportDirectory->Base;

				if (ExportDirectory->NumberOfFunctions > NumberOfExportFunctions)
				{
					return STATUS_BUFFER_TOO_SMALL;
				}

				for (INT i = 0; i < ExportDirectory->NumberOfFunctions; i++)
				{
					UINT_PTR          OriginalFuncAddress = 0;
					CHAR*             szFunctionName;
					UINT_PTR          FunctionOrdinals;
					UINT_PTR          FunctionAddress;

					szFunctionName = (CHAR*)((PUINT8)KernelBase + AddressOfNames[i]);
					FunctionOrdinals = AddressOfNameOrdinals[i] + Base - 1;			 // ?????????????????
					FunctionAddress = (UINT_PTR)((PUINT8)KernelBase + AddressOfFunctions[FunctionOrdinals]);

					if (GetExportFunctionAddress((PUINT8)ModuleInfo->szFileData, szFunctionName, &OriginalFuncAddress, TRUE))   // 文件格式 获得函数原地址
					{
						OriginalFuncAddress += (UINT_PTR)ModuleInfo->BaseAddress;
						DbgPrint("OriFuncAddr: %p\r\n", OriginalFuncAddress);
					}

					OutBuffer->ExportFunction[OutBuffer->NumberOfExportFunctions].CurFuncAddress = FunctionAddress;
					OutBuffer->ExportFunction[OutBuffer->NumberOfExportFunctions].OriFuncAddress = OriginalFuncAddress;

					memcpy(OutBuffer->ExportFunction[OutBuffer->NumberOfExportFunctions].szFunctionName, szFunctionName, strlen(szFunctionName));

					OutBuffer->NumberOfExportFunctions++;
				}
				//OutBuffer->NumberOfExportFunctions = ExportDirectory->NumberOfFunctions;

				//////////////////////////////////////////////////////////////////////////
				if (ModuleInfo != NULL && ModuleInfo->szFileData != NULL && MmIsAddressValid(ModuleInfo->szFileData))
				{
					DbgPrint("ExFreePool(ModuleFile->szFileData)\r\n");
					ExFreePool(ModuleInfo->szFileData);
				}

				return STATUS_SUCCESS;
			}
			
		}
	}

	return STATUS_UNSUCCESSFUL;
}


NTSTATUS 
QueryKrnlFileEATFunction(OUT PVOID OutputBuffer, IN UINT32 OutputLength, IN CHAR* szModuleFile)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DbgPrint("GetModuleInforNtoskrnl now:::\r\n");

	if (GetKrnlFileModuleInfo(&g_KrnlFileBase, &g_KrnlFileSize, g_szKrnlFileFullPath, szModuleFile))
	{
		DbgPrint("GetModuleInforNtoskrnl Success\r\n");
	}

	Status = EnumEATTable((PVOID)g_KrnlFileBase, (PEAT_INFORMATION)OutputBuffer, OutputLength, szModuleFile);

	return Status;
}



NTSTATUS
EnumKrnlFileFunctions(IN INT iKrnlFile, OUT PVOID OutputBuffer, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	switch (iKrnlFile)
	{
	case PH_KRNLFILE_NTOSKRNL_IAT:
	{
		DbgPrint("NtosKrnl IAT\r\n");

		Status = QueryKrnlFileIATFunction(OutputBuffer, OutputLength, "ntoskrnl.exe");

		break;
	}
	case PH_KRNLFILE_NTOSKRNL_EAT:
	{
		DbgPrint("NtosKrnl IAT\r\n");

		Status = QueryKrnlFileEATFunction(OutputBuffer, OutputLength, "ntoskrnl.exe");

		break;
	}
	case PH_KRNLFILE_WIN32K_IAT:
	{
		DbgPrint("Win32k IAT\r\n");

		Status = QueryKrnlFileIATFunction(OutputBuffer, OutputLength, "win32k.sys");

		break;
	}
	case PH_KRNLFILE_WIN32K_EAT:
	{
		DbgPrint("Win32k EAT\r\n");

		Status = QueryKrnlFileEATFunction(OutputBuffer, OutputLength, "win32k.sys");

		break;
	}
	case PH_KRNLFILE_HALDLL_IAT:
	{
		DbgPrint("Hal IAT\r\n");

		Status = QueryKrnlFileIATFunction(OutputBuffer, OutputLength, "hal.dll");

		break;
	}
	case PH_KRNLFILE_HALDLL_EAT:
	{
		DbgPrint("Hal EAT\r\n");

		Status = QueryKrnlFileEATFunction(OutputBuffer, OutputLength, "hal.dll");

		break;
	}
	default:
		break;
	}



	return Status;

}