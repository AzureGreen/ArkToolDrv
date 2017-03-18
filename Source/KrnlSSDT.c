#include "KrnlSSDT.h"
#include "Private.h"


UINT_PTR  g_ServiceTableBase = 0;

KIRQL     g_Irql = 0;




/************************************************************************
*  Name : GetKeServiceDescriptorTable
*  Param: SSDTAddress		SSDT地址 （OUT）
*  Ret  : BOOLEAN
*  获得SSDT地址 （x86 搜索导出表/x64 硬编码，算偏移）
************************************************************************/

BOOLEAN
GetKeServiceDescriptorTable(OUT PUINT_PTR SSDTAddress)
{
#ifdef _WIN64
	/*
	kd> rdmsr c0000082
	msr[c0000082] = fffff800`03e81640
	*/
	PUINT8	StartSearchAddress = (PUINT8)__readmsr(0xC0000082);   // fffff800`03ecf640
	PUINT8	EndSearchAddress = StartSearchAddress + 0x500;
	PUINT8	i = NULL;
	UINT8   v1 = 0, v2 = 0, v3 = 0;
	INT32   iOffset = 0;    // 002320c7 偏移不会超过4字节
	UINT64  VariableAddress = 0;

	*SSDTAddress = 0;
	for (i = StartSearchAddress; i<EndSearchAddress; i++)
	{
		/*
		kd> u fffff800`03e81640 l 500
		nt!KiSystemCall64:
		fffff800`03e81640 0f01f8          swapgs
		......

		nt!KiSystemServiceRepeat:
		fffff800`03e9c772 4c8d15c7202300  lea     r10,[nt!KeServiceDescriptorTable (fffff800`040ce840)]
		fffff800`03e9c779 4c8d1d00212300  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`040ce880)]
		fffff800`03e9c780 f7830001000080000000 test dword ptr [rbx+100h],80h


		TargetAddress = CurrentAddress + Offset + 7
		fffff800`040ce840 = fffff800`03e9c772 + 0x002320c7 + 7
		*/


		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			v1 = *i;
			v2 = *(i + 1);
			v3 = *(i + 2);
			if (v1 == 0x4c && v2 == 0x8d && v3 == 0x15)		// 硬编码  lea r10
			{
				memcpy(&iOffset, i + 3, 4);
				*SSDTAddress = iOffset + (UINT64)i + 7;
				break;
			}
		}
	}

	if (*SSDTAddress == 0)
	{
		return FALSE;
	}

#else

	/*

	kd> dd KeServiceDescriptorTable
	80553fa0  80502b8c 00000000 0000011c 80503000

	*/

	BOOLEAN bOk = FALSE;
	*SSDTAddress = 0;

	// 在Ntoskrnl.exe的导出表中，获取到KeServiceDescriptorTable地址
	bOk = GetNtosExportVariableAddress(L"KeServiceDescriptorTable", (PVOID*)SSDTAddress);

	if (bOk == FALSE)
	{
		return FALSE;
	}

#endif

	DbgPrint("SSDTAddress is %p\r\n", *SSDTAddress);

	return TRUE;
}


UINT_PTR
GetSSDTFunctionAddress(IN UINT32 FunctionIndex)
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE SSDTAddress = 0;
	BOOLEAN bOk = GetKeServiceDescriptorTable(&(UINT_PTR)SSDTAddress);

	if (bOk)
	{
		if (FunctionIndex < SSDTAddress->NumberOfServices)
		{

#ifdef _WIN64

			UINT32 Offset = SSDTAddress->ServiceTableBase[FunctionIndex];

			Offset >>= 4;

			return (UINT_PTR)((PUINT8)SSDTAddress->ServiceTableBase + Offset);

#else
			return (SSDTAddress->ServiceTableBase)[FunctionIndex];

#endif // _WIN64

		}
	}

	return 0;
}



VOID 
WPOFF()
{
	UINT_PTR cr0 = 0;
	g_Irql = KeRaiseIrqlToDpcLevel();
	cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	//_disable();

}

VOID 
WPON()
{
	UINT_PTR cr0 = __readcr0();
	cr0 |= 0x10000;
	//_enable();
	__writecr0(cr0);
	KeLowerIrql(g_Irql);
}


NTSTATUS
ResumeSSDTHook(IN UINT32 FunctionIndex, IN UINT_PTR OriginalAddress)
{
	// 64Bit存放的是偏移

	UINT32 Offset = (OriginalAddress - (UINT_PTR)g_ServiceTableBase);		// 计算出偏移

	Offset <<= 4;         // 没有管参数个数

	WPOFF();
	((PUINT32)g_ServiceTableBase)[FunctionIndex] = Offset;
	WPON();

	return STATUS_SUCCESS;
}