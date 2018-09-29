# rdpbotblocker

## Purpose
This was made as a countermeasure to constant login attempts from the internet when a Remote Desktop Protocol (RDP) endpoint is available on the internet.  There is some botnet or other malware or research that attempts a slow motion brute force attack using TONS of different source ip addresses. It is desired leave internet access open, but respond to these attacks.

## What is it
This app is a Windows service that monitors the Windows and Remote Desktop event logs to block suspicious IP addresses via Windows Firewall.  If it encounters a Security log event 4625 event, by default it will block the IP if there were 5 or more failures in the past hour. When it encounters RDP log event 140, it will immediately block the IP.  This was based on my inability to generate event 140 during my testing. Only the bot seemed to generate it. 

## Powershell inside C# process
A unique feature of this Windows service is that it can run Powershell scripts inside it's own process.  This enables the code to update Windows Firewall to use the simple powershell commands instead of some verbose c# code.

## Building
Open .sln file with Visual Studio 2017 and build solution in Debug or Release mode.

## Installing and configuring
Copy built binary (under AdaptiveFirewall.exe\bin\Release for example) to an installation folder of your choosing and install the service using InstallUtil.exe. It's not recommended to leave it in the build output folder as you may want to test additional builds when the service is running. 

Also copy the .config file along with the .exe and edit the file to configure your local subnets. If any IP addresses originate from a configured subnet they will be ignored. The appSetting "LocalSubnets" is a comma seperated list of subnets in CIDR notation (i.e. "10.10.10.1/24").

I made a folder called c:\Program files (x86)\Adaptive Firewall for my install.

Once binary and config file are copied, it is important to Install the service:

InstallUtil.exe c:\Program Files (x86)\Adaptive Firewall\AdaptiveFirewallService.exe

InstallUtil.exe is a Visual Studio utility so launch the VS command prompt to use it.  I plan on making a proper installer someday.
