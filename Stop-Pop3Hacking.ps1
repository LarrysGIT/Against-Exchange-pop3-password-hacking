
Set-Location (Get-Item ($MyInvocation.MyCommand.Definition)).DirectoryName

$POP3LogFilePath = 'D:\Program Files\Microsoft\Exchange Server\V15\Logging\Pop3'

<# Typical settings for Pop3 logging
LogFileLocation                   : D:\Program Files\Microsoft\Exchange Server\V15\Logging\Pop3
LogFileRollOverSettings           : Daily
LogPerFileSizeQuota               : 1.907 MB (2,000,000 bytes)
#>

# Change along with task scheduler trigger
$MinutesToBack = 1

$Date = Get-Date
$strDate = $Date.ToString('yyyy-MM-dd')

$End_Time = $Date.ToUniversalTime()
$Start_Time = $End_Time.AddMinutes(-$MinutesToBack)


$LogFolder = '.\Logs'
$strLogFile = "$LogFolder\${strDate}.txt"
$strLogFile_e = "$LogFolder\${strDate}_e.txt"

Set-Content -Path $strLogFile_e -Value $null

$WhiteList = @(Get-Content -Path 'FW_WhiteList.txt' -Encoding UTF8 -ErrorAction:SilentlyContinue | ?{$_ -and $_ -imatch '^[^#]'})
$BlackList = @(Get-Content -Path 'FW_BlackList.txt' -Encoding UTF8 -ErrorAction:SilentlyContinue | ?{$_ -and $_ -imatch '^[^#]'})

# threshold for ip not matching whitelist,
# 30 means total number of auth failure in past {MinutesToBack} minutes,
# 1 means number of different accounts auth failed,
# IPs matched both rules are identified as attacking
$t_AuthErr_fw = @(30, 1)
# threshold for whitelist ip
$t_AuthErr_fw_Intranet = @(50, 1)
# default block time, in seconds, which is 2 years
$t_AuthErr_fw_TimeoutDefault = 525600

$Mail_From = "$($env:COMPUTERNAME)<ITInfraAlerts@larry.song>"
$Mail_To = 'someoneA@larry.song', 'someoneB@larry.song'
$Mail_Subject = 'POP3 IP attacking warning'

# smtp server to sent warning email
$Mail_SMTPServer = 'smtpserver.larry.song'

function Add-Log
{
    PARAM(
        [String]$Path,
        [String]$Value,
        [String]$Type = 'Info'
    )
    $Type = $Type.ToUpper()
    $Date = Get-Date
    Write-Host "$($Date.ToString('[HH:mm:ss] '))[$Type] $Value" -ForegroundColor $(
        switch($Type)
        {
            'WARNING' {'Yellow'}
            'Error' {'Red'}
            default {'White'}
        }
    )
    if($Path){
        Add-Content -LiteralPath $Path -Value "$($Date.ToString('[HH:mm:ss] '))[$Type] $Value" -Encoding UTF8 -ErrorAction:SilentlyContinue
    }
}

Add-Log -Path $strLogFile_e -Value "Catch logs after : $($Start_time.ToString('HH:mm:ss'))"
Add-Log -Path $strLogFile_e -Value "Catch logs before: $($End_time.ToString('HH:mm:ss'))"

$AuthErr = @{}
Get-ChildItem -Path $POP3LogFilePath -Filter "*$($End_time.ToString('yyyyMMdd'))*" | ?{
    $_.LastWriteTimeUtc -gt $Start_time
} | %{Import-Csv $_.FullName} | ?{$_.context -imatch 'AuthFailed'} | %{
    $AuthErr.$([regex]::Match($_.cIp, '^(\d+\.){3}\d+').Value) += @($_.user)
}

Add-Log -Path $strLogFile_e -Value "Total POP3 AuthErr logs count : [$($AuthErr.Count)]"

$GoBlock = @{}
foreach($IP in $AuthErr.Keys)
{
    $t_AuthErr_fw_Timeout = $t_AuthErr_fw_TimeoutDefault
    $tmp = @($AuthErr.$IP | Group-Object | Sort-Object Count -Descending)
    Add-Log -Path $strLogFile_e -Value "In past [${MinutesToBack}] minute [IP address][errors][account][top 5]:[$IP][$($AuthErr.$IP.Count)][$($tmp.Count)][$($tmp[0..4] | %{$_.Name, $_.Count -join ':'})]"
    $tmpx = @($WhiteList | ?{$IP -imatch $_})
    if($tmpx)
    {
        Add-Log -Path $strLogFile_e -Value "[$IP] in white list, matched: [$($tmpx -join '][')]"
        if($tmpx -imatch 'supper')
        {
            Add-Log -Path $strLogFile_e -Value "[$IP] Matched as supper white list"
            continue
        }
        $tempx = $null
        $tempx = @([regex]::Matches($tmpx, 'Timeout:(\d+)') | %{[int]($_.Groups[1].Value)} | Sort-Object -Descending)[0]
        $t_AuthErr_fw_Timeout = $tempx
        if($AuthErr.$IP.Count -ge $t_AuthErr_fw_Intranet[0] -and $tmp.Count -ge $t_AuthErr_fw_Intranet[1])
        {
            Add-Log -Path $strLogFile_e -Value "[${IP}:$t_AuthErr_fw_Timeout] in whitelist,but excceed threshold for whitelist, adding into firewall" -Type Warning
            $GoBlock.$IP = $t_AuthErr_fw_Timeout
        }
    }
    else
    {
        Add-Log -Path $strLogFile_e -Value "[$IP] not in white list"
        if($AuthErr.$IP.Count -ge $t_AuthErr_fw[0] -and $tmp.Count -ge $t_AuthErr_fw[1])
        {
            $tmp.Name | Add-Content -Path "$LogFolder\$IP.log" -Encoding UTF8
            Add-Log -Path $strLogFile_e -Value "[${IP}:$t_AuthErr_fw_Timeout] excceed threshold" -Type Warning
            $GoBlock.$IP = $t_AuthErr_fw_Timeout
        }
    }
}

$Mail = $false

if($GoBlock)
{
    foreach($IP in $GoBlock.Keys)
    {
        if(!(Get-NetFirewallRule -DisplayName "ScriptAuto_Pop3Block_$IP" -ErrorAction:SilentlyContinue))
        {
            $Mail = $true
            New-NetFirewallRule -DisplayName "ScriptAuto_Pop3Block_$IP" -Profile Any -Action Block -RemoteAddress $IP -Protocol Tcp -LocalPort 110 -Direction Inbound -Description $Date.AddMinutes($GoBlock.$IP).ToString('yyyy-MM-dd HH:mm:ss') -ErrorAction:SilentlyContinue
            if(!$?)
            {
                Add-Log -Path $strLogFile_e -Value "[$IP] failed to add to firewall, cause:" -Type Error
                Add-Log -Path $strLogFile_e -Value $Error[0] -Type Error
            }
            else
            {
                Add-Log -Path $strLogFile_e -Value "[$IP] succeed add into firewall" -Type Warning
            }
        }
    }
}

Get-NetFirewallRule -DisplayName "ScriptAuto_Pop3*" | %{
    if($_.Description)
    {
        if(([datetime]($_.Description) - $Date).TotalMinutes -lt 0)
        {
            $_ | Remove-NetFirewallRule
        }
    }
    else
    {
        $_ | Remove-NetFirewallRule
    }

    $x = $_
    $WhiteList | ?{$_ -imatch 'supper'} | %{
        if($x.DisplayName -imatch $_)
        {
            $x | Remove-NetFirewallRule
        }
    }
}

$BlackList | %{
    if(!(Get-NetFirewallRule -DisplayName "ScriptAuto_Pop3BlackList_$_" -ErrorAction:SilentlyContinue))
    {
        New-NetFirewallRule -DisplayName "ScriptAuto_Pop3BlackList_$_" -Profile Any -Action Block -RemoteAddress $_ -Direction Inbound -Description ($Date.AddYears(100).ToString('yyyy-MM-dd HH:mm:ss')) -ErrorAction:SilentlyContinue
    }
}

If($Mail)
{
    try
    {
        Send-MailMessage -From $Mail_From -To $Mail_To -Subject $Mail_Subject -SmtpServer $Mail_SMTPServer -Body ((Get-Content $strLogFile_e -Encoding Default) -join "`t`n") -Encoding utf8
    }
    catch
    {
        Add-Log -Path $strLogFile_e -Value "Failed to send mail, cause: $($Error[0])" -Type Error
    }
}

Get-Content -Path $strLogFile_e -Encoding UTF8 | Add-Content -Path $strLogFile -Encoding UTF8
Add-Log -Path $strLogFile_e -Value 'Completed'
