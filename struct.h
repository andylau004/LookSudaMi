/*

Module : struct.h

Author : sudami [sudami@163.com]
Time   : 08/02/28

Comment:
申明一些函数和结构体

*/

#include "pe.h"

//////////////////////////////////////////////////////////////////////


typedef void  *HMODULE;
typedef long NTSTATUS, *PNTSTATUS;
typedef unsigned long DWORD;
typedef DWORD * PDWORD;
typedef unsigned long ULONG;
typedef unsigned long ULONG_PTR;
typedef ULONG *PULONG;
typedef unsigned short WORD;
typedef unsigned char BYTE; 
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef void *PVOID;
typedef BYTE BOOLEAN;
#define SEC_IMAGE    0x01000000

#define SID_MAX_SUB_AUTHORITIES         15
#define STANDARD_RIGHTS_READ	0x20000
#define TOKEN_QUERY             (0x0008)
#define TOKEN_READ       (STANDARD_RIGHTS_READ     |\
                          TOKEN_QUERY)

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

//////////////////////////////////////////////////////////////////////
//                                                                  // 
//                       申明 结构体                                //
//                                                                  // 
//////////////////////////////////////////////////////////////////////


typedef struct _OBJECT_CREATE_INFORMATION {
    ULONG Attributes;
    HANDLE RootDirectory;
    PVOID ParseContext;
    KPROCESSOR_MODE ProbeMode;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG SecurityDescriptorCharge;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;
    union {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };
    POBJECT_TYPE Type;
    UCHAR NameInfoOffset;
    UCHAR HandleInfoOffset;
    UCHAR QuotaInfoOffset;
    UCHAR Flags;

    union {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _MODULE_INFORMATION {	
	ULONG	dwImageBase;				
	PUCHAR	hModule;					// 只用这个就够了。保存我们映射的模块基址
} MODULE_INFORMATION,*PMODULE_INFORMATION;


typedef enum _KAPC_ENVIRONMENT {
  OriginalApcEnvironment,
  AttachedApcEnvironment,
  CurrentApcEnvironment,
  InsertApcEnvironment
} KAPC_ENVIRONMENT;

//  PEB
   
#pragma pack(4)
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
#pragma pack() 

typedef struct _PEB_ORIG {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[229];
    PVOID Reserved3[59];
    ULONG SessionId;
} PEB_ORIG, *PPEB_ORIG;

typedef void (*PPEBLOCKROUTINE)(PVOID PebLock);

struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK *Next;
	ULONG Size;
};
typedef struct _PEB_FREE_BLOCK PEB_FREE_BLOCK;
typedef struct _PEB_FREE_BLOCK *PPEB_FREE_BLOCK;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingPositionLeft;
	ULONG StartingPositionTop;
	ULONG Width;
	ULONG Height;
	ULONG CharWidth;
	ULONG CharHeight;
	ULONG ConsoleTextAttributes;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PPEBLOCKROUTINE FastPebLockRoutine;
	PPEBLOCKROUTINE FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID *KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PPEB_FREE_BLOCK FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	BYTE Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID **ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	ULONG PostProcessInitRoutine;
	ULONG TlsExpansionBitmap;
	BYTE TlsExpansionBitmapBits[0x80];
	ULONG SessionId;
} PEB, *PPEB;


typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SpareUl2;
    ULONG SpareUl3;
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    ULONG PageFaultCount;
    ULONG PeakWorkingSetSize;
    ULONG WorkingSetSize;
    ULONG QuotaPeakPagedPoolUsage;
    ULONG QuotaPagedPoolUsage;
    ULONG QuotaPeakNonPagedPoolUsage;
    ULONG QuotaNonPagedPoolUsage;
    ULONG PagefileUsage;
    ULONG PeakPagefileUsage;
    ULONG PrivatePageCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;


struct _SYSTEM_THREADS
{
	LARGE_INTEGER		KernelTime;
	LARGE_INTEGER		UserTime;
	LARGE_INTEGER		CreateTime;
	ULONG				WaitTime;
	PVOID				StartAddress;
	CLIENT_ID			ClientIs;
	KPRIORITY			Priority;
	KPRIORITY			BasePriority;
	ULONG				ContextSwitchCount;
	ULONG				ThreadState;
	KWAIT_REASON		WaitReason;
};


struct _SYSTEM_PROCESSES
{
	ULONG				NextEntryDelta;
	ULONG				ThreadCount;
	ULONG				Reserved[6];
	LARGE_INTEGER		CreateTime;
	LARGE_INTEGER		UserTime;
	LARGE_INTEGER		KernelTime;
	UNICODE_STRING		ProcessName;
	KPRIORITY			BasePriority;
	ULONG				ProcessId;
	ULONG				InheritedFromProcessId;
	ULONG				HandleCount;
	ULONG				Reserved2[2];
	VM_COUNTERS			VmCounters;
	IO_COUNTERS			IoCounters; //windows 2000 only
	struct _SYSTEM_THREADS	Threads[1];
};


// PROCESS_BASIC_INFORMATION
#ifdef  PROCESS_BASIC_INFORMATION
#undef  PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
	DWORD ExitStatus;
    DWORD PebBaseAddress;
    DWORD AffinityMask;
    DWORD BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
#endif


// SYSTEM_HANDLE_INFORMATION
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
     USHORT UniqueProcessId;
     USHORT CreatorBackTraceIndex;
     UCHAR ObjectTypeIndex;
     UCHAR HandleAttributes;
     USHORT HandleValue;   // 句柄
     PVOID Object;         // 若HANDLE类型为线程,则它是ETHREAD结构
     ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
     ULONG NumberOfHandles;
     SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


// SYSTEM_MODULE_INFORMATION
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG	Reserved[2];
	PVOID	Base;
	ULONG	Size;
	ULONG	Flags;
	USHORT  Index;
	USHORT  Unknown;
	USHORT  LoadCount;
	USHORT  ModuleNameOffset;
	CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


typedef struct {
    ULONG   dwNumberOfModules;
    SYSTEM_MODULE_INFORMATION   smi;
} MODULES, *PMODULES;


// SYSTEM_BASIC_INFORMATION
typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Unknown;                  //Always contains zero
	ULONG MaximumIncrement;         //一个时钟的计量单位
	ULONG PhysicalPageSize;         //一个内存页的大小
	ULONG NumberOfPhysicalPages;    //系统管理着多少个页
	ULONG LowestPhysicalPage;       //低端内存页
	ULONG HighestPhysicalPage;      //高端内存页
	ULONG AllocationGranularity;
	ULONG LowestUserAddress;        //地端用户地址
	ULONG HighestUserAddress;       //高端用户地址
	ULONG ActiveProcessors;         //激活的处理器
	UCHAR NumberProcessors;         //有多少个处理器
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;


// SYSTEM_INFORMATION_CLASS
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,  // 11
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,  // 0x10 -- 16
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemUnused1,
    SystemPerformanceTraceInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemUnused3,
    SystemUnused4,
    SystemUnused5,
    SystemUnused6,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation
} SYSTEM_INFORMATION_CLASS;



typedef struct _SID_IDENTIFIER_AUTHORITY {
  UCHAR  Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
  UCHAR  Revision;
  UCHAR  SubAuthorityCount;
  SID_IDENTIFIER_AUTHORITY  IdentifierAuthority;
  ULONG  SubAuthority[ANYSIZE_ARRAY];
} SID, *PISID;

typedef struct _SID_AND_ATTRIBUTES {
  PSID  Sid;
  ULONG  Attributes;
} SID_AND_ATTRIBUTES, * PSID_AND_ATTRIBUTES;


typedef struct _TOKEN_USER { 
	SID_AND_ATTRIBUTES User; 
} TOKEN_USER, *PTOKEN_USER; 

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

typedef struct _SERVICE_RECORD {
	struct _SERVICE_RECORD *PreviousServiceRecord; // next struct
	struct _SERVICE_RECORD *NextServiceRecord; // previous one
	WCHAR *Lp_WideServiceName;    // service name
	WCHAR *Dupe_WideServiceName;  // display name
	ULONG struct_size;          
	ULONG unknown0;
	ULONG sErv;
	ULONG unknown1;
	WCHAR *Lp_WideFullServicePath; // full path :)   
	ULONG dwServiceType;           // startup type
	ULONG dwCurrentState;          // service state
} SERVICE_RECORD, *PSERVICE_RECORD;

typedef struct   // FileInformationClass == FileBothDirectoryInformation 	
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER   CreationTime;
	LARGE_INTEGER   LastAccessTime;
	LARGE_INTEGER   LastWriteTime;
	LARGE_INTEGER   ChangeTime;
	LARGE_INTEGER   EndOfFile;
	LARGE_INTEGER   AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	WCHAR         FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;


typedef struct   // FileInformationClass == FileDirectoryInformation
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER   CreationTime;
	LARGE_INTEGER   LastAccessTime;
	LARGE_INTEGER   LastWriteTime;
	LARGE_INTEGER   ChangeTime;
	LARGE_INTEGER   EndOfFile;
	LARGE_INTEGER   AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct   // FileInformationClass == FileIdBothDirectoryInformation
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER   CreationTime;
	LARGE_INTEGER   LastAccessTime;
	LARGE_INTEGER   LastWriteTime;
	LARGE_INTEGER   ChangeTime;
	LARGE_INTEGER   EndOfFile;
	LARGE_INTEGER   AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER   File_Id;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct   // FileInformationClass ==FileIdFullDirectoryInformation 
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER   CreationTime;
	LARGE_INTEGER   LastAccessTime;
	LARGE_INTEGER   LastWriteTime;
	LARGE_INTEGER   ChangeTime;
	LARGE_INTEGER   EndOfFile;
	LARGE_INTEGER   AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	LARGE_INTEGER   File_Id;
	WCHAR         FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct  // FileInformationClass == FileFullDirectoryInformation
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER   CreationTime;
	LARGE_INTEGER   LastAccessTime;
	LARGE_INTEGER   LastWriteTime;
	LARGE_INTEGER   ChangeTime;
	LARGE_INTEGER   EndOfFile;
	LARGE_INTEGER   AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;


typedef struct   // FileInformationClass == FileNamesInformation
{
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	ULONG         FileNameLength;
	WCHAR         FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            PVOID LoadedImports;
        };
    };
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef
VOID
(*PLOAD_IMAGE_NOTIFY_ROUTINE)(
    IN PUNICODE_STRING FullImageName,
    IN HANDLE ProcessId,                // pid into which image is being mapped
    IN PIMAGE_INFO ImageInfo
    );

typedef NTSTATUS (NTAPI *PSREMOVECREATETHREADNOTIFYROUTINE)(
	IN PCREATE_THREAD_NOTIFY_ROUTINE  NotifyRoutine
	);

PSREMOVECREATETHREADNOTIFYROUTINE   _PsRemoveCreateThreadNotifyRoutine;




    #define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL

    //
    // Thread create failed
    //

    #define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL

    //
    // Debugger isn't shown this thread
    //

    #define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL

    //
    // Thread is impersonating
    //

    #define PS_CROSS_THREAD_FLAGS_IMPERSONATING        0x00000008UL

    //
    // This is a system thread
    //

    #define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL

    //
    // Hard errors are disabled for this thread
    //

    #define PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED 0x00000020UL

    //
    // We should break in when this thread is terminated
    //

    #define PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION 0x00000040UL

    //
    // This thread should skip sending its create thread message
    //
    #define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL

    //
    // This thread should skip sending its final thread termination message
    //
    #define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL




//////////////////////////////////////////////////////////////////////
//                                                                  // 
//                       申明   函数                                //
//                                                                  // 
//////////////////////////////////////////////////////////////////////

typedef NTSTATUS (*ZWCLOSE) (
							 IN HANDLE  Handle
							 );
ZWCLOSE Orig_ZwClose;


typedef NTSTATUS (*ZWENUMERATEKEY)(
								   IN HANDLE  KeyHandle,
								   IN ULONG  Index,
								   IN KEY_INFORMATION_CLASS  KeyInformationClass,
								   OUT PVOID  KeyInformation,
								   IN ULONG  Length,
								   OUT PULONG  ResultLength
								   );  
ZWENUMERATEKEY Orig_ZwEnumerateKey;


typedef NTSTATUS (*ZWQUERYDIRECTORYFILE)(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG FileInformationLength,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan
	);
ZWQUERYDIRECTORYFILE Orig_ZwQueryDirectoryFile;


typedef NTSTATUS (*ZWLOADDRIVER)(
								 IN PUNICODE_STRING  DriverServiceName
								 );
ZWLOADDRIVER Orig_ZwLoadDriver;


typedef NTSTATUS (*ZWSAVEKEY)(
							  IN HANDLE KeyHandle,
							  IN HANDLE FileHandle
							  );
ZWSAVEKEY Orig_ZwSaveKey;


typedef NTSTATUS (*ZWDELETEKEY)(
								IN HANDLE  KeyHandle
								);
ZWDELETEKEY Orig_ZwDeleteKey;


typedef  NTSTATUS (*ZWDELETEVALUEKEY)(
									  IN HANDLE  KeyHandle,
									  IN PUNICODE_STRING  ValueName
									  );
ZWDELETEVALUEKEY Orig_ZwDeleteValueKey;

/*--------------------------------------------------------------------*/

NTSTATUS 
fake_ZwClose(
			 IN HANDLE  Handle
			 );

NTSYSAPI
NTSTATUS
NTAPI
fake_ZwEnumerateKey(
					IN HANDLE  KeyHandle,
					IN ULONG  Index,
					IN KEY_INFORMATION_CLASS  KeyInformationClass,
					OUT PVOID  KeyInformation,
					IN ULONG  Length,
					OUT PULONG  ResultLength
					);

NTSYSAPI
NTSTATUS
NTAPI 
fake_ZwQueryDirectoryFile(
						  IN HANDLE FileHandle,
						  IN HANDLE Event OPTIONAL,
						  IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
						  IN PVOID ApcContext OPTIONAL,
						  OUT PIO_STATUS_BLOCK IoStatusBlock,
						  OUT PVOID FileInformation,
						  IN ULONG FileInformationLength,
						  IN FILE_INFORMATION_CLASS FileInformationClass,
						  IN BOOLEAN ReturnSingleEntry,
						  IN PUNICODE_STRING FileName OPTIONAL,
						  IN BOOLEAN RestartScan
						  );

NTSTATUS 
fake_ZwLoadDriver(
				  IN PUNICODE_STRING  DriverServiceName
				  );

NTSTATUS
fake_ZwSaveKey(
			   IN HANDLE KeyHandle,
			   IN HANDLE FileHandle
			   );

NTSTATUS 
fake_ZwDeleteKey(
				 IN HANDLE  KeyHandle
				 );

NTSTATUS 
fake_ZwDeleteValueKey(
					  IN HANDLE  KeyHandle,
					  IN PUNICODE_STRING  ValueName
					  );

NTSTATUS
PsSetLoadImageNotifyRoutine(
    IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    );

NTSTATUS
PsRemoveLoadImageNotifyRoutine(
    IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    );

NTSTATUS
  PsSetCreateProcessNotifyRoutine(
    IN PCREATE_PROCESS_NOTIFY_ROUTINE  NotifyRoutine,
    IN BOOLEAN  Remove
    );

PKEVENT
IoCreateNotificationEvent(
    IN PUNICODE_STRING EventName,
    OUT PHANDLE EventHandle
    );

NTSTATUS
PsLookupProcessByProcessId(
    IN HANDLE ProcessId,
    OUT PEPROCESS *Process
    );

NTSTATUS
  PsRemoveLoadImageNotifyRoutine(
    IN PLOAD_IMAGE_NOTIFY_ROUTINE  NotifyRoutine 
    );


VOID
KeInitializeApc (
         PKAPC Apc,
         PETHREAD Thread,
         KAPC_ENVIRONMENT Environment,
         PKKERNEL_ROUTINE KernelRoutine,
         PKRUNDOWN_ROUTINE RundownRoutine,
         PKNORMAL_ROUTINE NormalRoutine,
         KPROCESSOR_MODE ProcessorMode,
         PVOID NormalContext
         );

BOOLEAN
KeInsertQueueApc (
    PRKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
    );




/*--------------------------------------------------------------------*/

////////////////////////////////////////////////////////////////////////////////


void AddObjectToHide (WCHAR **Tab, PULONG Nb, WCHAR *Object);

DWORD 
NTAPI 
GetHeaders (
			PCHAR ibase,
			PIMAGE_FILE_HEADER      *pfh,
			PIMAGE_OPTIONAL_HEADER  *poh,
			PIMAGE_SECTION_HEADER   *psh
			);

PIMAGE_SECTION_HEADER 
FindModuleSectionHdr (
					  PVOID module, 
					  const char *section
					  );

NTSTATUS
GetEProcessByName (
				   WCHAR *processname, 
				   PEPROCESS *proc
				   );

NTSTATUS 
HideFromSCManager (
				   WCHAR *service
				   );

VOID MyDpcRoutine (
				   IN PKDPC Dpc, 
				   IN PVOID DeferredContext, 
				   IN PVOID sys1, 
				   IN PVOID sys2
				   );

DWORD 
GetDllFunctionAddress (
  char* lpFunctionName, 
  PUNICODE_STRING pDllName
  );

NTSTATUS
DevCreateClose(
			   IN PDEVICE_OBJECT  DeviceObject,
			   IN PIRP  Irp
			   );

NTSTATUS
DevDispatch(
			IN PDEVICE_OBJECT  DeviceObject,
			IN PIRP  Irp
			);

VOID OnUnload( IN PDRIVER_OBJECT DriverObject );

VOID
Thread_WriteReg (
    IN PVOID StartContext
    );

VOID
Thread_WriteReg_IE (
    IN PVOID StartContext
    );

VOID
Thread_WriteSDT (
    IN PVOID StartContext
    );

VOID
BreakKrnl(
	PDRIVER_OBJECT pDrvObject
	);

NTSTATUS GetUserName();

BOOL StartThread_reg_IE ();
void MySetTimer ();
VOID MyStartHook ();
VOID GetOrigAddr ();
NTSTATUS UnhideFromSCManager();
NTSTATUS SetSysRegKey(HANDLE Key);
NTSTATUS SetRegKey_IE(HANDLE Key);
BOOL IsExistSDT(PWCHAR FullPath);
BOOL StartThread_reg ();
BOOL StartThread_sdt ();
VOID MyUnHook ();
int __cdecl _snwprintf(wchar_t *, size_t, const wchar_t *, ...);
int swprintf( wchar_t *, const wchar_t *, ... );


VOID
MyLoadImageRoutine(
    IN PUNICODE_STRING ImageName,
    IN HANDLE ProcessId,
    IN PIMAGE_INFO ImageInfo
    );

VOID 
ProcessCreateMon ( 
				  IN HANDLE  hParentId, 
				  IN HANDLE PId,
				  IN BOOLEAN bCreate
				  );

ULONG  GetProcessNameOffset( void );

VOID GetRoutineAddr();

VOID 
FindKeAcquireInStackQueuedSpinLockRaiseToSynchAddr ();

ULONG 
GetFunctionAddr( 
				IN PCWSTR FunctionName
				);

BOOL IsExsitProc();

BOOL StartThread_Kill ();

VOID
Thread_KillProc (
				 IN PVOID StartContext
				 );

VOID
FindPsXXAddr();

VOID 
DoFind (
		IN PVOID pContext
		);

ULONG GetThreadFlagsOffset();

BOOLEAN
My_KeInsertQueueApc (
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
	);

PETHREAD
SD_PsGetNextProcessThread(
	PEPROCESS Process,
	PETHREAD Thread 
	);

BOOLEAN
ReferenceObject( 
				PVOID Object
				);


NTSTATUS
My_TerminateProc (
				  PEPROCESS Process,
				  NTSTATUS ExitStatus
				  );

VOID 
XPGetPsGetNextProcessThread();


ULONG
RVA2Offset (
	ULONG RVA, 
	PIMAGE_SECTION_HEADER pSectionHeader, 
	ULONG Sections
	);

ULONG 
Offset2RVA (
	ULONG Offset, 
	PIMAGE_SECTION_HEADER pSectionHeader, 
	ULONG Sections
	);

VOID XPRestoreKeInsertQueueApc ();
VOID XPRestoreKiInsertQueueApc ();
VOID XPRestorePspTerminateThreadByPointer ();
VOID XPRestoreNtTerminateProcess ();
VOID XPRestorePsGetNextProcessThread  ();

VOID HookKiInsertQueueApc ();
VOID UnHookKiInsertQueueApc ();
VOID fake_KiInsertQueueApc( PKAPC Apc,KPRIORITY Increment );
VOID Proxy_KiInsertQueueApc( PKAPC Apc, KPRIORITY Increment );



VOID
Thread_WriteReg_Group (
				 IN PVOID StartContext
				 );

BOOL StartThread_reg_Group();

BOOL IsMPExist();

////////////////////////////////////----- END OF FILE ------////////////////////////////////////////////