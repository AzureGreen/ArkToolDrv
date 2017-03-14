#include "SysThread.h"

extern DYNAMIC_DATA	g_DynamicData;

extern PEPROCESS    g_SystemEProcess;

/************************************************************************
*  Name : GetPspCidTableAddress
*  Ret  : UINT_PTR     PspCidTable地址
*  通过PsLookupProcessByProcessId的硬编码获得PspCidTable地址
************************************************************************/

UINT_PTR
GetPspCidTableAddress()
{
	PVOID PsLookupProcessByProcessIdAddress = NULL;

	GetNtosExportVariableAddress(L"PsLookupProcessByProcessId", (PVOID*)&PsLookupProcessByProcessIdAddress);

	if (PsLookupProcessByProcessIdAddress != NULL)
	{
		PUINT8	StartSearchAddress = NULL;
		PUINT8	EndSearchAddress = NULL;
		PUINT8	i = NULL;
		UINT8   v1 = 0, v2 = 0, v3 = 0;
		INT32   iOffset = 0;    // 64位下使用 ffed4991 偏移不会超过4字节(大地址在前，小地址在后)

		StartSearchAddress = PsLookupProcessByProcessIdAddress;
		EndSearchAddress = StartSearchAddress + 0x200;

#ifdef _WIN64
		/*
		3: kd> u PsLookupProcessByProcessId l 20
		nt!PsLookupProcessByProcessId:
		fffff800`041a11fc 48895c2408      mov     qword ptr [rsp+8],rbx
		fffff800`041a1201 48896c2410      mov     qword ptr [rsp+10h],rbp
		fffff800`041a1206 4889742418      mov     qword ptr [rsp+18h],rsi
		fffff800`041a120b 57              push    rdi
		fffff800`041a120c 4154            push    r12
		fffff800`041a120e 4155            push    r13
		fffff800`041a1210 4883ec20        sub     rsp,20h
		fffff800`041a1214 65488b3c2588010000 mov   rdi,qword ptr gs:[188h]
		fffff800`041a121d 4533e4          xor     r12d,r12d
		fffff800`041a1220 488bea          mov     rbp,rdx
		fffff800`041a1223 66ff8fc4010000  dec     word ptr [rdi+1C4h]
		fffff800`041a122a 498bdc          mov     rbx,r12
		fffff800`041a122d 488bd1          mov     rdx,rcx
		fffff800`041a1230 488b0d9149edff  mov     rcx,qword ptr [nt!PspCidTable (fffff800`04075bc8)]
		fffff800`041a1237 e834480200      call    nt!ExMapHandleToPointer (fffff800`041c5a70)
		*/

		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 7))
			{
				v1 = *i;
				v2 = *(i + 1);
				v3 = *(i + 7);
				if (v1 == 0x48 && v2 == 0x8b && v3 == 0xe8)		// 488b0d后面有重复出现的，所以+7判断e8
				{
					UINT_PTR PspCidTable = 0;
					RtlCopyMemory(&iOffset, i + 3, 4);
					PspCidTable = iOffset + (UINT64)i + 7;
					DbgPrint("PspCidTable :%p\r\n", PspCidTable);
					return PspCidTable;
				}
			}
		}

#else
		/*
		0: kd> u PsLookupProcessByProcessId l 20
		nt!PsLookupProcessByProcessId:
		840a3575 8bff            mov     edi,edi
		840a3577 55              push    ebp
		840a3578 8bec            mov     ebp,esp
		840a357a 83ec0c          sub     esp,0Ch
		840a357d 53              push    ebx
		840a357e 56              push    esi
		840a357f 648b3524010000  mov     esi,dword ptr fs:[124h]
		840a3586 33db            xor     ebx,ebx
		840a3588 66ff8e84000000  dec     word ptr [esi+84h]
		840a358f 57              push    edi
		840a3590 ff7508          push    dword ptr [ebp+8]
		840a3593 8b3d349ff883    mov     edi,dword ptr [nt!PspCidTable (83f89f34)]
		840a3599 e8d958feff      call    nt!ExMapHandleToPointer (84088e77)
		*/

		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 6))
			{
				v1 = *i;
				v2 = *(i + 1);
				v3 = *(i + 6);
				if (v1 == 0x8b && v2 == 0x3d && v3 == 0xe8)		// 488b0d后面有重复出现的，所以+7判断e8
				{
					*PspCidTable = *(PUINT32)(i + 2);
					DbgPrint("PspCidTable :%p\r\n", *PspCidTable);
					break;
				}
			}
		}
#endif // _WIN64

	}

	return 0;
}

/************************************************************************
*  Name : EnumGradeOneHandleTable
*  Param: TableCode
*  Ret  : VOID
*  遍历一级表
************************************************************************/

VOID
EnumGradeOneHandleTable(IN UINT_PTR TableCode, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION pti, IN UINT32 NumberOfThreads)
{
	/*
	Win7 x64 过16字节
	1: kd> dq fffff8a0`00fc2000
	fffff8a0`00fc2000  00000000`00000000 00000000`fffffffe
	fffff8a0`00fc2010  fffffa80`1acb3041 fffff780`00000000
	fffff8a0`00fc2020  fffffa80`1a989b61 00000000`00000000
	fffff8a0`00fc2030  fffffa80`1a98a301 00000000`00000000
	fffff8a0`00fc2040  fffffa80`1a98d061 fffff880`00000000
	fffff8a0`00fc2050  fffffa80`1ab8a061 fffffa80`00000000
	fffff8a0`00fc2060  fffffa80`1a99a061 fffff8a0`00000000
	fffff8a0`00fc2070  fffffa80`1a99bb61 00000000`00000000

	Win7 x86 过8字节
	0: kd> dd 8b404000
	8b404000  00000000 fffffffe 863d08a9 00000000		// 过前8个字节
	8b404010  863d05d1 00000000 863efd49 00000000
	8b404020  863f3bb9 00000000 863eb8d9 00000000
	8b404030  863f7021 00000000 863f74a9 00000000
	8b404040  863f3021 00000000 863f34d1 00000000
	8b404050  863fb021 00000000 863fb919 00000000
	8b404060  863fb641 00000000 863fb369 00000000
	8b404070  863f5021 00000000 863f5d49 00000000
	*/

	PHANDLE_TABLE_ENTRY	HandleTableEntry = (*(PUINT_PTR)TableCode + g_DynamicData.HandleTableEntryOffset);

	for (UINT32 i = 0; i < 0x200; i++)		// 512个表项
	{
		if (MmIsAddressValid((PVOID)&(HandleTableEntry->NextFreeTableEntry)))
		{
			if (HandleTableEntry->NextFreeTableEntry == 0 &&
				HandleTableEntry->Object != NULL &&
				MmIsAddressValid(HandleTableEntry->Object))
			{
				PVOID Object = (PVOID)(((UINT_PTR)HandleTableEntry->Object) & 0xFFFFFFFFFFFFFFF8);
				// 在FillProcessThreadInfo会判断由传入的Object转成的EProcess是否是SystemEprocess
				FillProcessThreadInfo((PETHREAD)Object, EProcess, pti, NumberOfThreads);
			}
		}
		HandleTableEntry++;
	}
}


/************************************************************************
*  Name : EnumGradeTwoHandleTable
*  Param: TableCode
*  Ret  : VOID
*  遍历二级表
************************************************************************/

VOID
EnumGradeTwoHandleTable(IN UINT_PTR TableCode, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION pti, IN UINT32 NumberOfThreads)
{
	/*
	Win7 x64
	2: kd> dq 0xfffff8a0`00fc5000
	fffff8a0`00fc5000  fffff8a0`00005000 fffff8a0`00fc6000
	fffff8a0`00fc5010  fffff8a0`0180b000 fffff8a0`02792000
	fffff8a0`00fc5020  00000000`00000000 00000000`00000000

	Win7 x86
	0: kd> dd 0xa4aaf000
	a4aaf000  8b404000 a4a56000 00000000 00000000
	*/

	do
	{
		EnumGradeOneHandleTable(TableCode, EProcess, pti, NumberOfThreads);		// fffff8a0`00fc5000..../ fffff8a0`00fc5008....
		TableCode += sizeof(UINT_PTR);

	} while (*(PUINT_PTR)TableCode != 0 && MmIsAddressValid((PVOID)*(PUINT_PTR)TableCode));

}

/************************************************************************
*  Name : EnumGradeThreeHandleTable
*  Param: TableCode
*  Ret  : VOID
*  遍历三级表
************************************************************************/

VOID
EnumGradeThreeHandleTable(IN UINT_PTR TableCode, IN PEPROCESS EProcess, OUT PPROCESS_THREAD_INFORMATION pti, IN UINT32 NumberOfThreads)
{
	do
	{
		EnumGradeTwoHandleTable(TableCode, EProcess, pti, NumberOfThreads);
		TableCode += sizeof(UINT_PTR);

	} while (*(PUINT_PTR)TableCode != 0 && MmIsAddressValid((PVOID)*(PUINT_PTR)TableCode));

}


NTSTATUS
EnumSystemThread(OUT PVOID OutputBuffer, IN UINT32 OutputLength)
{
	PPROCESS_THREAD_INFORMATION pti = (PPROCESS_THREAD_INFORMATION)OutputBuffer;
	UINT32 NumberOfThreads = (OutputLength - sizeof(PROCESS_THREAD_INFORMATION)) / sizeof(PROCESS_THREAD_ENTRY_INFORMATION);

	PETHREAD EThread = PsGetCurrentThread();
	UINT8    PreviousMode = ChangeThreadMode(EThread, KernelMode);

	UINT_PTR PspCidTable = GetPspCidTableAddress();

	ChangeThreadMode(EThread, PreviousMode);

	// EnumHandleTable
	if (PspCidTable)
	{
		PHANDLE_TABLE	HandleTable = NULL;
		
		HandleTable = (PHANDLE_TABLE)(*(PUINT_PTR)PspCidTable);  	// HandleTable = fffff8a0`00004910
		if (HandleTable && MmIsAddressValid((PVOID)HandleTable))
		{
			UINT8			GardeOfTable = 0;		// 指示句柄表层数
			UINT_PTR		TableCode = 0;			// 地址存放句柄表首地址

			TableCode = HandleTable->TableCode & 0xFFFFFFFFFFFFFFFC;	// TableCode = 0xfffff8a0`00fc5000
			GardeOfTable = HandleTable->TableCode & 0x03;				// GardeOfTable = 0x01

			if (TableCode && MmIsAddressValid((PVOID)TableCode))
			{
				switch (GardeOfTable)
				{
				case 0:
				{
					// 一层表
					EnumGradeOneHandleTable(TableCode, g_SystemEProcess, pti, NumberOfThreads);
					break;
				}
				case 1:
				{
					// 二层表
					EnumGradeTwoHandleTable(TableCode, g_SystemEProcess, pti, NumberOfThreads);
					break;
				}
				case 2:
				{
					// 三层表
					EnumGradeThreeHandleTable(TableCode, g_SystemEProcess, pti, NumberOfThreads);
					break;
				}
				default:
					break;
				}

				return STATUS_SUCCESS;
			}
		}
	}
	
	return STATUS_UNSUCCESSFUL;
}