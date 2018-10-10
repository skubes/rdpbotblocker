; Installer script for Inno setup
;
; Created and tested w/ 5.6.1
; http://www.jrsoftware.org/isdl.php

#ifndef BuildConfiguration
    #define BuildConfiguration "Release"
#endif

[Setup]
AppName=Adaptive Firewall
AppVersion=1.0
DefaultDirName={pf}\Adaptive Firewall
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\AdaptiveFirewallService.exe
Compression=lzma2
SolidCompression=yes
OutputDir=Output\{#BuildConfiguration}
OutputBaseFilename=AdaptiveFirewallSetup
SetupLogging=no

[Files]
Source: "..\AdaptiveFirewallService.exe\bin\{#BuildConfiguration}\AdaptiveFirewallService.exe"; DestDir: "{app}"; Flags: replacesameversion
Source: "..\AdaptiveFirewallService.exe\bin\{#BuildConfiguration}\AdaptiveFirewallService.exe.config"; DestDir: "{app}"; Flags: onlyifdoesntexist

[run]
Filename: {dotnet40}\InstallUtil.exe; Parameters: """{app}\AdaptiveFirewallService.exe""" ; Flags: runhidden

[UninstallRun]
Filename: {sys}\sc.exe; Parameters: "stop ""adaptive firewall""" ; Flags: runhidden
Filename: {dotnet40}\InstallUtil.exe; Parameters: "/u ""{app}\AdaptiveFirewallService.exe""" ; Flags: runhidden