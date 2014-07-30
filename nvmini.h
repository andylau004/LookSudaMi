#ifndef _SUDAMI_H
#define _SUDAMI_H 

#define FILE_DEVICE_SUDAMI	0x8000
#define SUDAMI_IOCTL_BASE	0x800

#define CTL_CODE_SUDAMI(i) CTL_CODE(FILE_DEVICE_SUDAMI, SUDAMI_IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUDAMI_HELLO	CTL_CODE_SUDAMI(0)
#define IOCTL_SUDAMI_TEST	CTL_CODE_SUDAMI(1)


#define SUDAMI_WIN32_DEVICE_NAME_A	"\\\\.\\sudami"
#define SUDAMI_WIN32_DEVICE_NAME_W	L"\\\\.\\sudami"
#define SUDAMI_DEVICE_NAME_A			"\\Device\\sudami"
#define SUDAMI_DEVICE_NAME_W			L"\\Device\\sudami"
#define SUDAMI_DOS_DEVICE_NAME_A		"\\DosDevices\\sudami"
#define SUDAMI_DOS_DEVICE_NAME_W		L"\\DosDevices\\sudami"
#define SUDAMI_EVENT_NAME_A             "\\BaseNamedObjects\\DL5CEvent"
#define SUDAMI_EVENT_NAME_W             L"\\BaseNamedObjects\\DL5CEvent"

#ifdef _UNICODE
#define SUDAMI_WIN32_DEVICE_NAME SUDAMI_WIN32_DEVICE_NAME_W
#define SUDAMI_DEVICE_NAME		SUDAMI_DEVICE_NAME_W
#define SUDAMI_DOS_DEVICE_NAME	SUDAMI_DOS_DEVICE_NAME_W
#define SUDAMI_EVENT_NAME        SUDAMI_EVENT_NAME_W 
#else
#define SUDAMI_WIN32_DEVICE_NAME SUDAMI_WIN32_DEVICE_NAME_A
#define SUDAMI_DEVICE_NAME		SUDAMI_DEVICE_NAME_A
#define SUDAMI_DOS_DEVICE_NAME	SUDAMI_DOS_DEVICE_NAME_A
#define SUDAMI_EVENT_NAME        SUDAMI_EVENT_NAME_A
#endif


/////////////////////////////////////////////////////////////////////

NTSTATUS
ObReferenceObjectByHandle (
						   IN HANDLE Handle,
						   IN ACCESS_MASK DesiredAccess,
						   IN POBJECT_TYPE ObjectType,
						   IN KPROCESSOR_MODE AccessMode,
						   OUT PVOID *Object,
						   OUT POBJECT_HANDLE_INFORMATION HandleInformation
						   );



NTSTATUS
ObQueryNameString(
				  IN  PVOID Object,
				  OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
				  IN  ULONG Length,
				  OUT PULONG ReturnLength
				  );

NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
							   IN ULONG SystemInformationClass,
							   IN PVOID SystemInformation,
							   IN ULONG SystemInformationLength,
							   OUT PULONG ReturnLength);

NTSTATUS
  ZwCreateEvent(
    OUT PHANDLE  EventHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN EVENT_TYPE  EventType,
    IN BOOLEAN  InitialState
    );

NTSTATUS
  ZwWaitForSingleObject(
    IN HANDLE  Handle,
    IN BOOLEAN  Alertable,
    IN PLARGE_INTEGER  Timeout OPTIONAL
    );

NTSYSAPI 
NTSTATUS
NTAPI
ZwNotifyChangeKey(
  IN HANDLE               KeyHandle,
  IN HANDLE               EventHandle,
  IN PIO_APC_ROUTINE      ApcRoutine,
  IN PVOID                ApcRoutineContext,
  IN PIO_STATUS_BLOCK     IoStatusBlock,
  IN ULONG                NotifyFilter,
  IN BOOLEAN              WatchSubtree,
  OUT PVOID               RegChangesDataBuffer,
  IN ULONG                RegChangesDataBufferLength,
  IN BOOLEAN              Asynchronous );

NTSTATUS 
RtlConvertSidToUnicodeString( 
	PUNICODE_STRING SidString, 
	PVOID Sid,
	BOOLEAN AllocateString 
	); 

NTSTATUS 
NtQueryInformationToken( 
	HANDLE Token, 
	TOKEN_INFORMATION_CLASS TokenInformationClass, 
	PVOID TokenInformation, 
	ULONG TokenInformationLength, 
	PULONG ReturnLength 
	); 

NTSTATUS 
ObOpenObjectByPointer( 
	PVOID Object, 
	ULONG Flags,	
	PACCESS_STATE AccessState, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_TYPE ObjectType, 
	KPROCESSOR_MODE AccessMode, 
	PHANDLE Handle
	); 

HANDLE 
PsReferencePrimaryToken (
	PEPROCESS Process 
	); 

NTSTATUS
  ZwOpenProcessTokenEx(
    IN HANDLE  ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN ULONG  HandleAttributes,
    OUT PHANDLE  TokenHandle
    );

NTSTATUS
  ZwOpenThreadTokenEx(
    IN HANDLE  ThreadHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN BOOLEAN  OpenAsSelf,
    IN ULONG  HandleAttributes,
    OUT PHANDLE  TokenHandle
    );

NTSTATUS
ZwQueryInformationProcess(
  IN HANDLE               ProcessHandle,
  IN PROCESSINFOCLASS     ProcessInformationClass,
  OUT PVOID               ProcessInformation,
  IN ULONG                ProcessInformationLength,
  OUT PULONG              ReturnLength 
  );

NTSTATUS 
ZwOpenProcess(
   OUT PHANDLE ProcessHandle, 
   IN ACCESS_MASK DesiredAccess, 
   IN POBJECT_ATTRIBUTES ObjectAttributes, 
   IN PCLIENT_ID ClientId
   );
 
NTSTATUS
RtlFormatCurrentUserKeyPath(
    OUT PUNICODE_STRING CurrentUserKeyPath
    );

VOID KeAttachProcess( PEPROCESS proc );
VOID KeDetachProcess();

NTSTATUS
  NtOpenFile(
    OUT PHANDLE  FileHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  ShareAccess,
    IN ULONG  OpenOptions
    );



/////////////////////////////////////////////////////////////////////

#endif


////////////////////////////////////----- END OF FILE ------////////////////////////////////////////////