

; --- MK ---
Name "Wolfguard"
OutFile "wolfguar.exe"
InstallDir "$PROGRAMFILES\Wolfguard"
RequestExecutionLevel admin

; --- MK ---
!include "MUI2.nsh"
!define MUI_ABORTWARNING

; --- MK ---
!define MUI_ICON "C:\MeuInstalador\1.ico"
!define MUI_UNICON "C:\MeuInstalador\1.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "PortugueseBR"

; --- MK ---
Section "Wolfguard (obrigatório)"
    SectionIn RO

    ; MK
    SetOutPath $INSTDIR

    ; MK
    File /r "C:\Users\mateu\Downloads\finalchale\dist\*.*"

    ; MK
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; MK
    CreateDirectory "$SMPROGRAMS\Wolfguard"
    CreateShortCut "$SMPROGRAMS\Wolfguard\Wolfguard.lnk" "$INSTDIR\wolfguard.exe"
    CreateShortCut "$DESKTOP\Wolfguard.lnk" "$INSTDIR\wolfguard.exe"
    CreateShortCut "$SMPROGRAMS\Wolfguard\Desinstalar Wolfguard.lnk" "$INSTDIR\uninstall.exe"

    ; MK
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wolfguard" "DisplayName" "Wolfguard"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wolfguard" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wolfguard" "Publisher" "WolfGuard"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wolfguard" "DisplayVersion" "1.0"

SectionEnd

; --- MK ---
Section "Uninstall"

    ; MK
    Delete "$INSTDIR\*.*"
    RMDir "$INSTDIR"

    ; MK
    Delete "$SMPROGRAMS\Wolfguard\*.*"
    RMDir "$SMPROGRAMS\Wolfguard"
    Delete "$DESKTOP\Wolfguard.lnk"

    ; MK
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wolfguard"

SectionEnd