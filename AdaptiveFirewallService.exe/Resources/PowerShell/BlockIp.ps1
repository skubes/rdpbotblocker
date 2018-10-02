<#
	Script run to block suspect Ips with Windows
	firewall.

	If "$FirewallRuleName" (set below) doesn't exist it will be created.
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
$FirewallRuleName = "AdaptiveFirewallService-Block RDP bots"
$CreateRule = $false
$InformationPreference = 'Continue'

try {
    Info "Checking firewall rule [$FirewallRuleName]"
    $rule = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction Stop
}
catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException]{

   if ($_.Exception.Message -like "No MSFT_NetFirewallRule objects found with property 'DisplayName' equal to*")
   {
       $CreateRule = $true
   }
   else {
       throw
   }
}

if ($CreateRule)
{
    Info "   firewall rule not found. Creating new rule and setting IP $IpAddress to blocked"
    # rule not found, create it
    $createArgs = @{
        DisplayName = $FirewallRuleName;
        Direction = 'Inbound';
        Action = 'Block';
        Enabled = 'False';
    }

    $rule = New-NetFirewallRule @createArgs
    $filter = $rule | Get-NetFirewallAddressFilter
    Set-NetFirewallAddressFilter -InputObject $filter -RemoteAddress $IpAddress
    Set-NetFirewallRule -InputObject $rule -Enabled True
    Info "Done."
    return
}

$filter = $rule | Get-NetFirewallAddressFilter
$existingIps = $filter.RemoteAddress
Info "   found [$($existingIps.Count)] existing IPs"

$distinctIps = New-Object 'Collections.Generic.HashSet[String]'
$existingIps |
    ForEach-Object {
        $distinctIps.Add($_) | Out-Null
}
$distinctIps.Add($IpAddress) | Out-Null
if ($distinctIps.Count -gt $existingIps.Count) {
    Set-NetFirewallAddressFilter -InputObject $filter -RemoteAddress $distinctIps
	Info "   updated firewall to block [$IpAddress]"
}
else {
	Info "   didn't have to update rule since [$IpAddress] is already blocked"
}
Info "Done."