param(
	[Parameter(Mandatory=$true)]
	[ValidateSet("Debug","Release")]
	$BuildConfiguration
)
$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition
$iscc = "C:\Program Files (x86)\Inno Setup 5\ISCC.exe"
&$iscc "/DBuildConfiguration=$BuildConfiguration" $scriptFolder\AdaptiveFirewall.iss
