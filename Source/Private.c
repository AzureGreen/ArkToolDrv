#include "Private.h"


extern DYNAMIC_DATA g_DynamicData;

PVOID								g_KernelBase = NULL;
UINT32								g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE	g_SSDTAddress = NULL;

typedef
NTSYSCALLAPI
NTSTATUS
(NTAPI * pfnNtQueryVirtualMemory)(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength);



/************************************************************************
*  Name : ZwQueryVirtualMemory
*  Param: ProcessHandle				���̾��			��IN��
*  Param: BaseAddress				����ѯ����ַ		��IN��
*  Param: MemoryInformationClass	ö����Ϣ			��IN��
*  Param: MemoryInformation			�洢�ڴ���Ϣ�Ļ�������OUT��
*  Param: MemoryInformationLength	����������			��IN��
*  Param: ReturnLength				���س���			��OUT��
*  Ret  : NTSTATUS
*  ͨ��NtQueryVirtualMemory��ѯ���������ڴ���Ϣ
************************************************************************/

NTSTATUS
NTAPI
ZwQueryVirtualMemory(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength)
{
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	pfnNtQueryVirtualMemory NtQueryVirtualMemory = (pfnNtQueryVirtualMemory)GetSSDTEntry(g_DynamicData.NtQueryVirtualMemoryIndex);
	if (NtQueryVirtualMemory != NULL)
	{
		// ����֮ǰ��ģʽ��ת��KernelMode
		PUINT8		PreviousMode = (PUINT8)PsGetCurrentThread() + g_DynamicData.PreviousMode;
		UINT8		Temp = *PreviousMode;

		*PreviousMode = KernelMode;

		Status = NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
			MemoryInformation, MemoryInformationLength, ReturnLength);

		*PreviousMode = Temp;

	}
	else
	{
		Status = STATUS_NOT_FOUND;
	}
	return Status;
}


/************************************************************************
*  Name : SearchPattern
*  Param: Pattern			��ƥ��Ӳ���루IN��
*  Param: MatchWord			ƥ���ַ���IN��
*  Param: PatternLength		��ƥ��Ӳ���볤�ȣ�IN��
*  Param: BaseAddress		��ƥ�����ַ��IN��
*  Param: BaseSize			��ַ���ȣ�IN��
*  Param: FoundAddress		ƥ����ɵĵ�ַ��OUT��
*  Ret  : BOOLEAN
*  ͨ���ַ���ƥ���㷨��Ӳ���룬�ҵ�ƥ��Ļ���ַ
************************************************************************/

NTSTATUS
SearchPattern(IN PUINT8 Pattern, IN UINT8 MatchWord, IN UINT_PTR PatternLength, IN const PVOID BaseAddress, IN UINT_PTR BaseSize, OUT PVOID* FoundAddress)
{
	if (FoundAddress == NULL || Pattern == NULL || BaseAddress == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	for (UINT_PTR i = 0; i < BaseSize - PatternLength; i++)
	{
		BOOLEAN bFound = TRUE;
		for (UINT_PTR j = 0; j < PatternLength; j++)
		{
			if (Pattern[j] != MatchWord && Pattern[j] != ((PUINT8)BaseAddress)[i + j])
			{
				bFound = FALSE;
				break;
			}
		}

		if (bFound != FALSE)
		{
			*FoundAddress = (PUINT8)BaseAddress + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}


/************************************************************************
*  Name : GetSSDTAddress
*  Param: SSDTAddress		����SSDT����ַ��OUT��
*  Ret  : BOOLEAN
*  ���SSDT����ַ
************************************************************************/

BOOLEAN GetSSDTAddress(OUT PSYSTEM_SERVICE_DESCRIPTOR_TABLE* SSDTAddress)
{
	PVOID KernelBase = NULL;

#ifdef _WIN64
	PIMAGE_NT_HEADERS		NtHeader = NULL;
	PIMAGE_SECTION_HEADER	FirstSection = NULL;
#else
	UNICODE_STRING			uniKeServiceDescriptorTable = { 0 };
#endif // _WIN64


	if (g_SSDTAddress != NULL)
	{
		*SSDTAddress = g_SSDTAddress;
		return TRUE;
	}

#ifdef _WIN64
	GetKernelBase(&KernelBase, NULL);
	if (KernelBase == NULL)
	{
		return FALSE;
	}

	NtHeader = RtlImageNtHeader(KernelBase);

	FirstSection = (PIMAGE_SECTION_HEADER)(NtHeader + 1);
	for (PIMAGE_SECTION_HEADER TravelSection = FirstSection; TravelSection < FirstSection + NtHeader->FileHeader.NumberOfSections; TravelSection++)
	{
		if (TravelSection->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
			TravelSection->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(TravelSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PUINT32)TravelSection->Name != 'TINI') &&
			(*(PUINT32)TravelSection->Name != 'EGAP'))
		{
			PVOID FoundAddress = NULL;

			/*
			kd> u KiSystemServiceRepeat
			nt!KiSystemServiceRepeat:
			fffff800`03e84772 4c8d15c7202300  lea     r10,[nt!KeServiceDescriptorTable (fffff800`040b6840)]
			fffff800`03e84779 4c8d1d00212300  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`040b6880)]
			fffff800`03e84780 f7830001000080000000 test dword ptr [rbx+100h],80h
			*/

			UINT8 PatternCode[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

			NTSTATUS Status = SearchPattern(PatternCode, 0xCC, sizeof(PatternCode) - 1, (PUINT8)KernelBase + TravelSection->VirtualAddress,
				TravelSection->Misc.VirtualSize, &FoundAddress);
			if (NT_SUCCESS(Status))
			{																					// Offset
				g_SSDTAddress = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUINT8)FoundAddress + *(PUINT32)((PUINT8)FoundAddress + 3) + 7);
				*SSDTAddress = g_SSDTAddress;
				break;
			}
		}
	}
#else
	// ��Ntoskrnl.exe�ĵ������У���ȡ��KeServiceDescriptorTable��ַ
	RtlUnicodeStringInit(&uniKeServiceDescriptorTable, L"KeServiceDescriptorTable");
	*SSDTAddress = MmGetSystemRoutineAddress(&uniKeServiceDescriptorTable);

#endif // _WIN64

	if (*SSDTAddress == NULL)
	{
		return FALSE;
	}

	return TRUE;
}


/************************************************************************
*  Name : GetKernelBase
*  Param: KernelBase		�ں�ģ�����ַ��OUT��
*  Param: KernelSize		ģ���С��OUT��
*  Ret  : BOOLEAN
*  ͨ��ZwQuerySystemInformation���ں˵���ȫ�ֱ�����ַ��ϲ����ں˵�һģ��
************************************************************************/

BOOLEAN GetKernelBase(OUT PVOID* KernelBase, OUT PUINT32 KernelSize)
{
	NTSTATUS			 Status = STATUS_UNSUCCESSFUL;

	PRTL_PROCESS_MODULES ProcessModules = NULL;

	PVOID				 BufferData = NULL;
	UINT32				 BufferLength = 0;

	UNICODE_STRING		 uniKernelRoutineName = { 0 };
	PVOID				 CheckAddress = NULL;

	if (g_KernelBase != NULL)
	{
		if (KernelSize)
		{
			*KernelSize = g_KernelSize;
			*KernelBase = g_KernelBase;
		}
		return TRUE;
	}

	// ����ں�ģ�鵼��ȫ�ֱ��������ĵ�ַ�����Դ���Ϊ�ж��ں˵�ַ
	RtlUnicodeStringInit(&uniKernelRoutineName, L"NtOpenFile");
	CheckAddress = MmGetSystemRoutineAddress(&uniKernelRoutineName);

	// ��ȡ�����ڴ泤�ȵĴ�С
	Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &BufferLength);		// ���BufferData���軺��������
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return FALSE;
	}

	BufferData = ExAllocatePool(PagedPool, BufferLength);   // PagedPool(���ݶ� �û�������)  NonPagedPool(����� ���û�������)
	if (BufferData == NULL)
	{
		return FALSE;
	}

	// ö��ϵͳģ�鵽BufferData��
	Status = ZwQuerySystemInformation(SystemModuleInformation, BufferData, BufferLength, &BufferLength);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(BufferData);
		return FALSE;
	}

	ProcessModules = (PRTL_PROCESS_MODULES)BufferData;

	for (UINT32 i = 0; i < ProcessModules->NumberOfModules; i++)
	{
		if ((UINT_PTR)CheckAddress >= (UINT_PTR)(ProcessModules->Modules[i].ImageBase) &&
			(UINT_PTR)CheckAddress <= (UINT_PTR)((PUINT8)ProcessModules->Modules[i].ImageBase + ProcessModules->Modules[i].ImageSize))
		{
			// Hit
			g_KernelBase = ProcessModules->Modules[i].ImageBase;
			g_KernelSize = ProcessModules->Modules[i].ImageSize;
			*KernelBase = g_KernelBase;
			if (KernelSize)
			{
				*KernelSize = g_KernelSize;
			}
			break;
		}
	}

	if (BufferData)
	{
		ExFreePool(BufferData);
		BufferData = NULL;
		ProcessModules = NULL;
	}
	return TRUE;
}

/************************************************************************
*  Name : GetSSDTEntry
*  Param: FunctionIndex		����������
*  Ret  : PVOID				����������ַ��
*  ͨ��������������SSDT���л�÷�������ַ
************************************************************************/

PVOID
GetSSDTEntry(IN UINT32 FunctionIndex)
{
	UINT32 KernelSize = 0;
	PVOID KernelBase = NULL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE  SSDTAddress = NULL;

	GetSSDTAddress(&SSDTAddress);

	GetKernelBase(&KernelBase, &KernelSize);

	if (SSDTAddress && KernelBase)
	{
		if (FunctionIndex > SSDTAddress->NumberOfServices)
		{
			return NULL;
		}

#ifdef _WIN64
		// 64λ�� SSDT����ÿһ���4�ֽڣ���28λ��Offset�������SSDTBaseAddress������4λ�Ǻ�����������
		return (PVOID)((PUINT8)SSDTAddress->ServiceTableBase + (((PUINT32)SSDTAddress->ServiceTableBase)[FunctionIndex] >> 4));
#else
		// 32λ�� SSDT����ÿһ��Ҳ��4�ֽڣ�ȫ�Ǻ������Ե�ַ
		return (PVOID)(SSDTAddress->ServiceTableBase[FunctionIndex]);
#endif // _WIN64

	}

	return NULL;
}


/************************************************************************
*  Name : MappingPEFileInKernelSpace
*  Param: wzFileFullPath		PE�ļ�����·��
*  Param: MappingBaseAddress	ӳ���Ļ���ַ ��OUT��
*  Param: MappingViewSize		�ļ�ӳ���С   ��OUT��
*  Ret  : BOOLEAN
*  ��PE�ļ�ӳ�䵽�ں˿ռ�
************************************************************************/

BOOLEAN
MappingPEFileInKernelSpace(IN WCHAR* wzFileFullPath, OUT PVOID* MappingBaseAddress, OUT PSIZE_T MappingViewSize)
{
	UNICODE_STRING    uniFileFullPath = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	NTSTATUS          Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK   Iosb = { 0 };
	HANDLE			  FileHandle = NULL;
	HANDLE			  SectionHandle = NULL;

	if (!wzFileFullPath || !MappingBaseAddress)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&uniFileFullPath, wzFileFullPath);		// ����ָ���ʽ����unicode
	InitializeObjectAttributes(&oa,									// ��ʼ�� oa
		&uniFileFullPath,											// Dll����·��
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,					// �����ִ�Сд | �ں˾��
		NULL,
		NULL
	);

	Status = IoCreateFile(&FileHandle,								// ����ļ����
		GENERIC_READ | SYNCHRONIZE,									// ͬ����
		&oa,														// �ļ�����·��
		&Iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING
	);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	//	oa.ObjectName = NULL;

	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwCreateSection(&SectionHandle,			// �����ڶ���,���ں����ļ�ӳ�� ��CreateFileMapping��
		SECTION_QUERY | SECTION_MAP_READ,
		&oa,
		NULL,
		PAGE_WRITECOPY,
		SEC_IMAGE,
		FileHandle
	);

	ZwClose(FileHandle);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	Status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),				// ӳ�䵽��ǰ���̵��ڴ�ռ��� System
		MappingBaseAddress,
		0,
		0,
		0,
		MappingViewSize,
		ViewUnmap,
		0,
		PAGE_WRITECOPY
	);

	ZwClose(SectionHandle);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************
*  Name : GetSSDTFunctionIndexFromNtdllExportTableByFunctionName
*  Param: szFindFunctionName	PE�ļ�����·��
*  Param: SSDTFunctionIndex	ӳ���Ļ���ַ ��OUT��
*  Ret  : BOOLEAN
*  ͨ������������ntdll.dll�ĵ������л��Ŀ�꺯����SSDT������
************************************************************************/

BOOLEAN
GetSSDTFunctionIndex(IN CHAR* szTargetFunctionName, OUT PUINT32 SSDTFunctionIndex)
{

#ifdef _WIN64

	/* Win7 64bit
	004> u zwopenprocess
	ntdll!ZwOpenProcess:
	00000000`774c1570 4c8bd1          mov     r10,rcx
	00000000`774c1573 b823000000      mov     eax,23h
	00000000`774c1578 0f05            syscall
	00000000`774c157a c3              ret
	00000000`774c157b 0f1f440000      nop     dword ptr [rax+rax]
	*/

	UINT32    Offset_SSDTFunctionIndexInNtdllExportFunctionAddress = 4;

#else

	/* 	Win7 32bit
	kd> u zwopenProcess
	nt!ZwOpenProcess:
	83e9162c b8be000000      mov     eax,0BEh
	83e91631 8d542404        lea     edx,[esp+4]
	83e91635 9c              pushfd
	83e91636 6a08            push    8
	83e91638 e8b1190000      call    nt!KiSystemService (83e92fee)
	83e9163d c21000          ret     10h
	*/

	/* WinXp 32bit
	kd> u zwopenprocess
	nt!ZwOpenProcess:
	804ff720 b87a000000      mov     eax,7Ah
	804ff725 8d542404        lea     edx,[esp+4]
	804ff729 9c              pushfd
	804ff72a 6a08            push    8
	804ff72c e850ed0300      call    nt!KiSystemService (8053e481)
	804ff731 c21000          ret     10h

	*/
	UINT32    Offset_SSDTFunctionIndexInNtdllExportFunctionAddress = 1;

#endif

	// ʹ���ڴ�ӳ�佫Ntdllģ��ӳ�䵽System���̵��ڴ�ռ���в���(Ntdll.dllģ��ĵ������н�������)

	WCHAR					wzFileFullPath[] = L"\\SystemRoot\\System32\\ntdll.dll";
	PVOID					MappingBaseAddress = NULL;
	SIZE_T					MappingViewSize = 0;
	PIMAGE_NT_HEADERS		NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PUINT32					AddressOfFunctions = NULL;			// offset
	PUINT32					AddressOfNames = NULL;				// offset
	PUINT16					AddressOfNameOrdinals = NULL;		// Ordinal
	CHAR*					szFunctionName = NULL;
	UINT32					FunctionOrdinal = 0;
	UINT_PTR				FunctionAddress = 0;
	BOOLEAN					bOk = FALSE;
	UINT32					i = 0;

	*SSDTFunctionIndex = -1;

	//��Ntdll.dll ��ǰ�Ŀռ���
	bOk = MappingPEFileInKernelSpace(wzFileFullPath, &MappingBaseAddress, &MappingViewSize);
	if (bOk == FALSE)
	{
		return FALSE;
	}

	__try
	{
		NtHeader = RtlImageNtHeader(MappingBaseAddress);		// ת����ntheader
		if (NtHeader && NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)MappingBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);		// �������ַ

			AddressOfFunctions = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfFunctions);
			AddressOfNames = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNames);
			AddressOfNameOrdinals = (PUINT16)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNameOrdinals);

			// ���ﲻ����ת����ntdllӦ�ò�����ת��
			for (i = 0; i < ExportDirectory->NumberOfNames; i++)
			{
				szFunctionName = (CHAR*)((PUINT8)MappingBaseAddress + AddressOfNames[i]);   // ��ú�������
				if (_stricmp(szFunctionName, szTargetFunctionName) == 0)						  // hit !
				{
					FunctionOrdinal = AddressOfNameOrdinals[i];
					FunctionAddress = (UINT_PTR)((PUINT8)MappingBaseAddress + AddressOfFunctions[FunctionOrdinal]);			// (WinXp 32bit 804ff720 ZwOpenProcess)		(Win7 32bit 83e9162c ZwOpenProcess)	(Win7 64bit 00000000`774c1570 ZwOpenProcess)

					// SSDT�к�������
					*SSDTFunctionIndex = *(PUINT32)(FunctionAddress + Offset_SSDTFunctionIndexInNtdllExportFunctionAddress);	// (WinXp 32bit 804ff721 7Ah)	(Win7 32bit 804ff721 0BEh)		(Win7 64bit 00000000`774c1574 23h)
					break;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		;
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), MappingBaseAddress);


	if (*SSDTFunctionIndex == -1)
	{
		return FALSE;
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////


BOOLEAN
GetSSSDTAddress( )
{

}

PVOID
GetSSSDTEntry()
{

}


BOOLEAN 
IsUnicodeStringValid(IN PUNICODE_STRING uniString)
{
	BOOLEAN bOk = FALSE;

	__try
	{
		if (uniString->Length > 0 &&
			uniString->Buffer		&&
			MmIsAddressValid(uniString->Buffer) &&
			MmIsAddressValid(&uniString->Buffer[uniString->Length / sizeof(WCHAR) - 1]))
		{
			bOk = TRUE;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		bOk = FALSE;
	}

	return bOk;
}