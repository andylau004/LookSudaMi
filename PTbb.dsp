# Microsoft Developer Studio Project File - Name="PTbb" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) External Target" 0x0106

CFG=PTbb - Win32 XP Checked
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "PTbb.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PTbb.mak" CFG="PTbb - Win32 XP Checked"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PTbb - Win32 XP Free" (based on "Win32 (x86) External Target")
!MESSAGE "PTbb - Win32 XP Checked" (based on "Win32 (x86) External Target")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "PTbb - Win32 XP Free"

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "ddkbuild -WLHXP free ."
# PROP Rebuild_Opt "-cZ"
# PROP Target_File "PTbb.sys"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "PTbb - Win32 XP Checked"

# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "ddkbuild -WLHXP checked ."
# PROP Rebuild_Opt "-cZ"
# PROP Target_File "PTbb.sys"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "PTbb - Win32 XP Free"
# Name "PTbb - Win32 XP Checked"

!IF  "$(CFG)" == "PTbb - Win32 XP Free"

!ELSEIF  "$(CFG)" == "PTbb - Win32 XP Checked"

!ENDIF 

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\HideService.c
# End Source File
# Begin Source File

SOURCE=.\nvmini.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\HideService.h
# End Source File
# Begin Source File

SOURCE=.\nvmini.h
# End Source File
# Begin Source File

SOURCE=.\pe.h
# End Source File
# Begin Source File

SOURCE=.\struct.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\sources
# End Source File
# End Target
# End Project
