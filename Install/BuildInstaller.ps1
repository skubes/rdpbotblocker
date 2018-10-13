param(
	[ValidateSet("Debug","Release")]
	$BuildConfiguration = "Release"
)

if ($env:SkipInstallerBuildEvent -eq 'true')
{
	return
}

$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Get Inno Setup install folder from registry (assumes x64 Windows)
try {
	$installDir = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 5_is1" -Name InstallLocation -ErrorAction Stop).InstallLocation
}
catch {
	Write-Error -ErrorRecord $_
	Write-Output "Couldn't detect Inno Setup installed on this system. Skipping installer build."
	Write-Output "If it's not installed, run innosetup-qsp-5.6.1.exe (in folder $scriptFolder)"
	Write-Output "or go to: http://www.jrsoftware.org/isdl.php"
	Write-Output "The .iss file was tested with Inno Setup v5.6.1"
	return
}

$iscc = Join-Path $installDir "ISCC.exe"

# call ISCC console compiler. (This also requires Inno Preprocessor
# to be installed to support defining BuildConfiguration variable here.)
&$iscc "/DBuildConfiguration=$BuildConfiguration" $scriptFolder\AdaptiveFirewall.iss