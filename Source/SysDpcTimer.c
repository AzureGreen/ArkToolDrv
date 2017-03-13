#include "SysDpcTimer.h"

typedef
BOOLEAN ( * pfnKeSetTimer)(
	__inout PKTIMER Timer,
	__in LARGE_INTEGER DueTime,
	__in_opt PKDPC Dpc);


/************************************************************************
*  Name : FindKiWaitVariableAddress
*  Param: KiWaitNeverAddress
*  Param: KiWaitAlwaysAddress
*  Ret  : BOOLEAN
*  ͨ�� KeSetTimer ��Ӳ���� ��� δ�������� KiWaitNeverAddress & KiWaitAlwaysAddress
************************************************************************/

BOOLEAN
FindKiWaitVariableAddress(OUT PUINT_PTR* KiWaitNeverAddress, OUT PUINT_PTR* KiWaitAlwaysAddress)
{
	pfnKeSetTimer KeSetTimer = NULL;

	GetNtosExportVariableAddress(L"KeSetTimer", (PVOID*)&KeSetTimer);

	if (KeSetTimer != NULL)
	{
		/*
			1: kd> u KeSetTimer l 50
			nt!KeSetTimer:
			fffff800`03ed28b0 4883ec38        sub     rsp,38h
			fffff800`03ed28b4 4c89442420      mov     qword ptr [rsp+20h],r8
			fffff800`03ed28b9 4533c9          xor     r9d,r9d
			fffff800`03ed28bc 4533c0          xor     r8d,r8d
			fffff800`03ed28bf e80c000000      call    nt!KiSetTimerEx (fffff800`03ed28d0)
			fffff800`03ed28c4 4883c438        add     rsp,38h
			fffff800`03ed28c8 c3              ret
			fffff800`03ed28c9 90              nop
			fffff800`03ed28ca 90              nop
			fffff800`03ed28cb 90              nop
			fffff800`03ed28cc 90              nop
			fffff800`03ed28cd 90              nop
			fffff800`03ed28ce 90              nop
			fffff800`03ed28cf 90              nop
			nt!KiSetTimerEx:
			fffff800`03ed28d0 48895c2408      mov     qword ptr [rsp+8],rbx
			fffff800`03ed28d5 4889542410      mov     qword ptr [rsp+10h],rdx
			fffff800`03ed28da 55              push    rbp
			fffff800`03ed28db 56              push    rsi
			fffff800`03ed28dc 57              push    rdi
			fffff800`03ed28dd 4154            push    r12
			fffff800`03ed28df 4155            push    r13
			fffff800`03ed28e1 4156            push    r14
			fffff800`03ed28e3 4157            push    r15
			fffff800`03ed28e5 4883ec50        sub     rsp,50h
			fffff800`03ed28e9 488b0530c82200  mov     rax,qword ptr [nt!KiWaitNever (fffff800`040ff120)]
			fffff800`03ed28f0 488b1d19c92200  mov     rbx,qword ptr [nt!KiWaitAlways (fffff800`040ff210)]

		*/

		UINT8   v1 = 0, v2 = 0, v3 = 0;
		PUINT8	StartSearchAddress = NULL;
		PUINT8	EndSearchAddress = NULL;
		PUINT8	i = NULL;
		INT32   iOffset = 0;

		StartSearchAddress = (PUINT8)KeSetTimer;
		EndSearchAddress = StartSearchAddress + 0x200;

		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
			{
				v1 = *i;
				v2 = *(i + 1);
				v3 = *(i + 2);
				if (v1 == 0x48 && v2 == 0x8b && v3 == 0x05)		// Ӳ����  mov rax
				{
					memcpy(&iOffset, i + 3, 4);
					*KiWaitNeverAddress = (PUINT64)(iOffset + (UINT64)i + 7);
					i += 7;
					memcpy(&iOffset, i + 3, 4);
					*KiWaitAlwaysAddress = (PUINT64)(iOffset + (UINT64)i + 7);
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

/************************************************************************
*  Name : TransTimerDPCEx
*  Param: Timer				Timer����
*  Param: KiWaitNeverAddress
*  Param: KiWaitAlwaysAddress
*  Ret  : PKDPC
*  ת��Timer�������DPCΪ��ʵ��DPC(���ǿ��ö�����ʽ)
************************************************************************/

PKDPC
TransTimerDPCEx(IN PKTIMER Timer, IN UINT64 KiWaitNeverAddress, IN UINT64 KiWaitAlwaysAddress)
{
	UINT_PTR Dpc = (UINT_PTR)Timer->Dpc;
	Dpc ^= KiWaitNeverAddress;
	Dpc = _rotl64(Dpc, (UINT8)(KiWaitNeverAddress & 0xFF));		//��ѭ�� �ƶ�Shiftλ
	Dpc ^= (UINT_PTR)Timer;
	Dpc = _byteswap_uint64(Dpc);
	Dpc ^= KiWaitAlwaysAddress;
	return (PKDPC)Dpc;
}


NTSTATUS
EnumDpcTimer(OUT PVOID OutputBuffer, IN UINT32 OutputLength)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PDPC_TIMER_INFORMATION dti = (PDPC_TIMER_INFORMATION)OutputBuffer;
	UINT32 NumberOfDpcTimers = (OutputLength - sizeof(DPC_TIMER_INFORMATION)) / sizeof(DPC_TIMER_ENTRY_INFORMATION);

	UINT32 CpuNumber = KeNumberProcessors;	// ȫ�ֱ��� CPU����

	INT i = 0, j = 0;

	for (i = 0; i < CpuNumber; i++)
	{
		BOOLEAN   bOk = FALSE;
		PUINT_PTR KiWaitAlwaysAddress = NULL;
		PUINT_PTR KiWaitNeverAddress = NULL;
		UINT_PTR  PrcbAddress = 0;
		PUINT8    TimerEntries = NULL;

		KeSetSystemAffinityThread(i + 1);	// ʹ��ǰ�߳������ڵ�һ���������ϣ���Ϊֻ�е�һ����������ֵ����Ч

		/*
			3: kd> rdmsr 0xc0000101
			msr[c0000101] = fffff880`045d5000

			3: kd> dq fffff880`045d5000+20		// ���KPRCB��ַ
			fffff880`045d5020  fffff880`045d5180 fffff880`045d57f0

			kd> dt _Kprcb
			ntdll!_KPRCB
			+0x000 MxCsr            : Uint4B
			+0x004 LegacyNumber     : UChar
			......
			+0x2200 TimerTable      : _KTIMER_TABLE

			3: kd> dt _KTIMER_TABLE
			nt!_KTIMER_TABLE
			   +0x000 TimerExpiry      : [64] Ptr64 _KTIMER
			   +0x200 TimerEntries     : [256] _KTIMER_TABLE_ENTRY

			3: kd> dt _KTIMER_TABLE_ENTRY fffff880`045d5180+2200+200
			nt!_KTIMER_TABLE_ENTRY
			+0x000 Lock             : 0
			+0x008 Entry            : _LIST_ENTRY [ 0xfffffa80`1a9c1e90 - 0xfffffa80`1a9c1e90 ]
			+0x018 Time             : _ULARGE_INTEGER 0x8`6ca34f0e

		*/

		PrcbAddress = (UINT_PTR)__readmsr(0xC0000101) + 0x20;
		
		KeRevertToUserAffinityThread();	  // �ָ��߳����еĴ�����

		TimerEntries = (PUINT8)(*(PUINT64)PrcbAddress + 0x2200 + 0x200);	// _KTIMER_TABLE_ENTRY

		bOk = FindKiWaitVariableAddress(&KiWaitNeverAddress, &KiWaitAlwaysAddress);
		if (bOk == TRUE)
		{
			KIRQL OldIrql = KeRaiseIrqlToDpcLevel();
			for (j = 0; j < 0x100; j++)  // 256��KTIMER_TABLE_ENTRY����
			{
				PLIST_ENTRY CurrentListEntry = (PLIST_ENTRY)(TimerEntries + sizeof(KTIMER_TABLE_ENTRY) * j + sizeof(UINT64));  // ÿ�ζ�λ�������List_Entry��Ա
				if (CurrentListEntry && MmIsAddressValid(CurrentListEntry))
				{
					for (PLIST_ENTRY TravelListEntry = CurrentListEntry->Flink;
						MmIsAddressValid(TravelListEntry) && CurrentListEntry != TravelListEntry;
						TravelListEntry = TravelListEntry->Flink)
					{
						//����׵�ַ
						PKTIMER Timer = CONTAINING_RECORD(TravelListEntry, KTIMER, TimerListEntry);
						/*
						kd> dt _KTIMER
						nt!_KTIMER
						+0x000 Header           : _DISPATCHER_HEADER
						+0x018 DueTime          : _ULARGE_INTEGER
						+0x020 TimerListEntry   : _LIST_ENTRY
						+0x030 Dpc              : Ptr64 _KDPC
						+0x038 Processor        : Uint4B
						+0x03c Period           : Uint4B
						*/
						PKDPC RealDpc = TransTimerDPCEx(Timer, *KiWaitNeverAddress, *KiWaitAlwaysAddress);
						if (MmIsAddressValid(Timer) && MmIsAddressValid(RealDpc) && MmIsAddressValid(RealDpc->DeferredRoutine))
						{
							UINT_PTR CurrentCount = dti->NumberOfDpcTimers;
							if (NumberOfDpcTimers > CurrentCount)
							{
								DbgPrint("DPC����:%p\r\n", (UINT_PTR)RealDpc);
								DbgPrint("DPC�������:%p\r\n", (UINT_PTR)RealDpc->DeferredRoutine);
								DbgPrint("Timer����:%p\r\n", (UINT_PTR)Timer);
								DbgPrint("��������:%d\r\n:", Timer->Period);
								
								dti->DpcTimer[CurrentCount].TimerObject = (UINT_PTR)Timer;
								dti->DpcTimer[CurrentCount].RealDpc = (UINT_PTR)RealDpc;
								dti->DpcTimer[CurrentCount].Cycle = Timer->Period;
								dti->DpcTimer[CurrentCount].TimeDispatch = (UINT_PTR)RealDpc->DeferredRoutine;
							}
							dti->NumberOfDpcTimers++;
							Status = STATUS_SUCCESS;
						}
					}
				}

			}
			KeLowerIrql(OldIrql);
		}
	}

	return Status;
}


NTSTATUS
RemoveDpcTimer(IN UINT_PTR TimerObject)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	
	if (TimerObject && MmIsAddressValid((PVOID)TimerObject))
	{
		if (KeCancelTimer((PKTIMER)TimerObject))
		{
			return STATUS_SUCCESS;
		}
	}
	
	return STATUS_UNSUCCESSFUL;
}