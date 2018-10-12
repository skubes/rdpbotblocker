# Adaptive Firewall (rdpbotblocker)

## Purpose
This Windows service was made as a countermeasure to constant login attempts from the internet when a Windows Remote Desktop Protocol (RDP) endpoint is available online.  There is some botnet or other malware (or research) that attempts a slow motion brute force attack on Windows RDP endpoints connected to the internet. It can use TONS of different source ip addresses. (I guess this is simply a consequence of hooking a machine up to the interwebs in 2018 and these login attempts don't seem to actually represent much risk.)

It is desired leave internet access open, but respond to these attacks by blocking the source IP addresses with Windows Firewall.

## What is it
This app is a Windows service that uses the EventLogWatcher .NET class to subscribe to events from the Windows Security event log and the Remote Desktop event log (`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`) and act on those events to block suspicious IP addresses on the internet (or untrusted networks) with Windows Firewall.  If it encounters a Security log event 4625 event, it will block the IP if there were 5 (by default) or more failures in the past hour. When it encounters RDP log event 140, it will immediately block the IP.  This was based on my inability to generate event 140 during my testing using normal interactive RDP clients (on Windows and Android). Normal clients will keep prompting for passwords indefinitely. Only the bots seemed to generate the 140 event. 

## Prerequisites
This program requires Windows with Windows Management Framework 5.1 installed and Windows Firewall turned on.

## Powershell inside C# process
A feature of this Windows service is that it hosts Powershell scripts inside it's process.  This enables easy management of Windows Firewall with simple powershell scripts instead of more verbose c# code.

## Building
Open .sln file with Visual Studio 2017 and build the solution in Debug or Release mode.

## Installing and configuring
The build will produce an installer in both Debug and Release mode.  See Install folder in the repository and install Inno Setup to enable the installer.
To run the installer build manaully, run BuildInstaller.ps1 with "release" or "debug" as an argument.

### **Important**
Be sure to edit the .config file that comes along with the .exe (in the install location) to configure your local subnets before starting the service for the first time. If any IP addresses originate from a configured subnet they will be ignored. The appSetting `LocalSubnets` is a comma seperated list of subnets in CIDR notation (i.e. "10.10.10.1/24").  If this setting is not configured properly the program could block local addresses and prevent all remote access to a system (requiring console access to recover).
