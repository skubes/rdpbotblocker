; Installer script for Inno setup
;
; Created and tested w/ 5.6.1
; http://www.jrsoftware.org/isdl.php

[Setup]
AppName=Adaptive Firewall
AppVersion=1.0
DefaultDirName={pf}\Adaptive Firewall
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\AdaptiveFirewallService.exe
Compression=lzma2
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=AdaptiveFirewallSetup
SetupLogging=no

[Files]
Source: "..\AdaptiveFirewallService.exe\bin\Release\AdaptiveFirewallService.exe"; DestDir: "{app}"
Source: "..\AdaptiveFirewallService.exe\bin\Release\AdaptiveFirewallService.exe.config"; DestDir: "{app}"

[run]
Filename: {dotnet40}\InstallUtil.exe; Parameters: """{app}\AdaptiveFirewallService.exe""" ; Flags: runhidden

[UninstallRun]
Filename: {sys}\sc.exe; Parameters: "stop ""adaptive firewall""" ; Flags: runhidden
Filename: {dotnet40}\InstallUtil.exe; Parameters: "/u ""{app}\AdaptiveFirewallService.exe""" ; Flags: runhidden