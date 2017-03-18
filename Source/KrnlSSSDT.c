#include "KrnlSSSDT.h"


BOOLEAN 
GetKeServiceDescriptorTableShadow(OUT PUINT_PTR SSSDTAddress)
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

	*SSSDTAddress = 0;
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


		3: kd> dq fffff800`042cc980
		fffff800`042cc980  fffff800`04095800 00000000`00000000
		fffff800`042cc990  00000000`00000191 fffff800`0409648c
		fffff800`042cc9a0  fffff960`000f1f00 00000000`00000000
		fffff800`042cc9b0  00000000`0000033b fffff960`000f3c1c
		fffff800`042cc9c0  c0000044`00000005 c0000044`00000005
		fffff800`042cc9d0  c000012c`00000000 c00000a1`00000000
		fffff800`042cc9e0  c0000001`00000002 00000000`76f311d6
		fffff800`042cc9f0  00000000`0000a237 00000000`00000000


		TargetAddress = CurrentAddress + Offset + 7
		fffff800`040ce840 = fffff800`03e9c772 + 0x002320c7 + 7
		*/

		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			v1 = *i;
			v2 = *(i + 1);
			v3 = *(i + 2);
			if (v1 == 0x4c && v2 == 0x8d && v3 == 0x1d)		// 硬编码  lea r11
			{
				memcpy(&iOffset, i + 3, 4);
				// 拿到了ShadowServiceDescriptorTable地址，他是一个数组，第一个成员是SSDT，第二个是SSSDT
				*SSSDTAddress = iOffset + (UINT64)i + 7;	
				*SSSDTAddress += sizeof(UINT_PTR) * 4;		// 过SSDT
				break;
			}
		}
	}

	if (*SSSDTAddress == 0)
	{
		return FALSE;
	}

#else

	

#endif

	DbgPrint("SSDTAddress is %p\r\n", *SSSDTAddress);

	return TRUE;
}

UINT_PTR
GetSSSDTFunctionAddress(IN UINT32 FunctionIndex)
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE SSSDTAddress = 0;
	BOOLEAN bOk = GetKeServiceDescriptorTableShadow(&(UINT_PTR)SSSDTAddress);

	if (bOk)
	{
		if (FunctionIndex < SSSDTAddress->NumberOfServices)
		{

#ifdef _WIN64

			UINT32 Offset = SSSDTAddress->ServiceTableBase[FunctionIndex];

			Offset >>= 4;

			return (UINT_PTR)((PUINT8)SSSDTAddress->ServiceTableBase + Offset);

#else
			return (SSSDTAddress->ServiceTableBase)[FunctionIndex];

#endif // _WIN64

		}
	}

	return 0;
}

