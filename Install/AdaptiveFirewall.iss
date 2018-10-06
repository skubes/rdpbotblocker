; -- Example2.iss --
; Same as Example1.iss, but creates its icon in the Programs folder of the
; Start Menu instead of in a subfolder, and also creates a desktop icon.

; SEE THE DOCUMENTATION FOR DETAILS ON CREATING .ISS SCRIPT FILES!

[Setup]
AppName=Adaptive Firewall
AppVersion=1.0
DefaultDirName={pf}\Adaptive Firewall
; Since no icons will be created in "{group}", we don't need the wizard
; to ask for a Start Menu folder name:
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