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
$FirewallRuleName = "AdaptiveFirwallService-Block RDP bots"
$CreateRule = $false
$InformationPreference = 'Continue'

try {
    Info "Getting exising blocked IPs from firewall rule [$FirewallRuleName]"
    $rule = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction Stop
}
catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException]{

   if ($_.Exception.Message -like 'No MSFT_NetFirewallRule objects found with property*')
   {
       $CreateRule = $true
   }
   else {
       throw
   }
}

if ($CreateRule)
{
    Info "Firewall rule not found. Creating new."
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
    Info "   done."
    return
}

$filter = $rule | Get-NetFirewallAddressFilter
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