<#
	Script run to block suspect Ips with Windows
	firewall.
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string] $IpAddress
)
function Info {
    Param($InfoMessage)
        Write-Information "{PowerShell script} $InfoMessage"
}

$InformationPreference = 'Continue'

Info "Getting exising blocked IPs from firewall rule (Block RDP Bots)"
$filter = Get-NetFirewallRule -DisplayName "Block RDP Bots" -ErrorAction Stop | Get-NetFirewallAddressFilter
$existingIps = $filter.RemoteAddress
Info "   found [$($existingIps.Count)] IPs"
Info "   done."

$distinctIps = New-Object 'Collections.Generic.HashSet[String]'
$existingIps |
    ForEach-Object {
        $distinctIps.Add($_) | Out-Null
}
$distinctIps.Add($IpAddress) | Out-Null
if ($distinctIps.Count -gt $existingIps.Count) {
        Set-NetFirewallAddressFilter -InputObject $filter -RemoteAddress $distinctIps
}