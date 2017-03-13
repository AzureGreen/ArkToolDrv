#ifndef CXX_NtStructs_H
#define CXX_NtStructs_H

#include <ntifs.h>

//////////////////////////////////////////////////////////////////////////
// Section���

typedef struct _CONTROL_AREA
{
	struct _SEGMENT*	Segment;
	LIST_ENTRY			DereferenceList;
	UINT_PTR			NumberOfSectionReferences;
	UINT_PTR			NumberOfPfnReferences;
	UINT_PTR			NumberOfMappedViews;
	UINT_PTR			NumberOfUserReferences;
	UINT32				u;
	UINT32				FlushInProgressCount;
	PFILE_OBJECT		FilePointer;
	UINT32				ControlAreaLock;
	UINT32				ModifiedWriteCount;
	UINT_PTR			WaitingForDeletion;
	UINT_PTR			u2;
	UINT64				Padding;
	UINT_PTR			LockedPages;
	LIST_ENTRY			ViewList;
} CONTROL_AREA, *PCONTROL_AREA;


typedef struct _SEGMENT
{
	PCONTROL_AREA	ControlArea;
	UINT32			TotalNumberOfPtes;
	UINT32			SegmentFlags;
	UINT_PTR		NumberOfCommittedPages;
	UINT64			SizeOfSegment;
	union
	{
		UINT_PTR ExtendInfo;
		UINT_PTR BasedAddress;
	} u;
	UINT_PTR	SegmentLock;
	UINT_PTR	u1;
	UINT_PTR	u2;
	UINT_PTR	PrototypePte;
#ifndef _WIN64
	UINT32		Padding;
#endif // !_WIN64
	UINT_PTR	ThePtes;
} SEGMENT, *PSEGMENT;


typedef struct _SECTION_OBJECT
{
	PVOID	 StartingVa;
	PVOID	 EndingVa;
	PVOID	 Parent;
	PVOID	 LeftChild;
	PVOID	 RightChild;
	PSEGMENT Segment;
} SECTION_OBJECT, *PSECTION_OBJECT;

//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Peb���
typedef struct _PEB_LDR_DATA32
{
	UINT32			Length;
	UINT8			Initialized;
	UINT32			SsHandle;
	LIST_ENTRY32	InLoadOrderModuleList;
	LIST_ENTRY32	InMemoryOrderModuleList;
	LIST_ENTRY32	InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32	 InLoadOrderLinks;
	LIST_ENTRY32	 InMemoryOrderLinks;
	LIST_ENTRY32	 InInitializationOrderLinks;
	UINT32			 DllBase;
	UINT32			 EntryPoint;
	UINT32			 SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	UINT32			 Flags;
	UINT16			 LoadCount;
	UINT16			 TlsIndex;
	LIST_ENTRY32	 HashLinks;
	UINT32			 TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
	UINT8 InheritedAddressSpace;
	UINT8 ReadImageFileExecOptions;
	UINT8 BeingDebugged;
	UINT8 BitField;
	UINT32 Mutant;
	UINT32 ImageBaseAddress;
	UINT32 Ldr;
	UINT32 ProcessParameters;
	UINT32 SubSystemData;
	UINT32 ProcessHeap;
	UINT32 FastPebLock;
	UINT32 AtlThunkSListPtr;
	UINT32 IFEOKey;
	UINT32 CrossProcessFlags;
	UINT32 UserSharedInfoPtr;
	UINT32 SystemReserved;
	UINT32 AtlThunkSListPtr32;
	UINT32 ApiSetMap;
} PEB32, *PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY		InLoadOrderLinks;
	LIST_ENTRY		InMemoryOrderLinks;
	LIST_ENTRY		InInitializationOrderLinks;
	PVOID			DllBase;
	PVOID			EntryPoint;
	UINT32			SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	UINT32			Flags;
	UINT16			LoadCount;
	UINT16			TlsIndex;
	LIST_ENTRY		HashLinks;
	UINT32			TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	UINT32 Length;
	UINT8 Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	UINT8 InheritedAddressSpace;
	UINT8 ReadImageFileExecOptions;
	UINT8 BeingDebugged;
	UINT8 BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID UserSharedInfoPtr;
	UINT32 SystemReserved;
	UINT32 AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;

//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// SystemInformationClass
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;

//////////////////////////////////////////////////////////////////////////
// ������
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	UINT16	UniqueProcessId;
	UINT16	CreatorBackTraceIndex;
	UINT8	ObjectTypeIndex;
	UINT8	HandleAttributes;
	UINT16	HandleValue;
	PVOID	Object;
	UINT32	GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// SystemHandleInformation
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	UINT32	NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define ObjectNameInformation	1
#define ObjectHandleFlagInformation 4

//////////////////////////////////////////////////////////////////////////
// �ڴ����
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation
#if DEVL
	, MemoryWorkingSetInformation
#endif
	, MemoryMappedFilenameInformation
	, MemoryRegionInformation
	, MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_BASIC_INFORMATION
{
	PVOID	BaseAddress;
	PVOID	AllocationBase;
	UINT32	AllocationProtect;
	SIZE_T	RegionSize;
	UINT32	State;
	UINT32	Protect;
	UINT32	Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// SSDT ��
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PUINT_PTR	ServiceTableBase;
	PUINT32		ServiceCounterTableBase;
	UINT_PTR	NumberOfServices;
	PUINT8		ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// ����ģ����Ϣ
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE	Section;
	PVOID	MappedBase;
	PVOID	ImageBase;
	UINT32	ImageSize;
	UINT32	Flags;
	UINT16	LoadOrderIndex;
	UINT16	InitOrderIndex;
	UINT16	LoadCount;
	UINT16	OffsetToFileName;
	UINT8	FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

// SystemModuleInformation
typedef struct _RTL_PROCESS_MODULES
{
	UINT32 NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
// ����Ŀ¼

#define NUMBER_HASH_BUCKETS 37
typedef struct _OBJECT_DIRECTORY_ENTRY
{
	struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
	struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[NUMBER_HASH_BUCKETS];
	EX_PUSH_LOCK Lock;
	struct _DEVICE_MAP *DeviceMap;
	ULONG SessionId;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

//////////////////////////////////////////////////////////////////////////
// IoTimer

typedef struct _IO_TIMER
{
	INT16				Type;
	INT16				TimerFlag;
#ifdef _WIN64
	UINT32				Unknown;
#endif
	LIST_ENTRY			TimerList;
	PVOID				TimerRoutine;
	PVOID				Context;
	PDEVICE_OBJECT		DeviceObject;
} IO_TIMER, *PIO_TIMER;

//////////////////////////////////////////////////////////////////////////
// Dpc

typedef struct _KTIMER_TABLE_ENTRY
{
	UINT64			Lock;
	LIST_ENTRY		Entry;
	ULARGE_INTEGER	Time;
} KTIMER_TABLE_ENTRY, *PKTIMER_TABLE_ENTRY;




#endif // !CXX_NtStructs_H
