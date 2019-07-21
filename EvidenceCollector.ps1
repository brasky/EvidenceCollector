param (
    [string]$controls = 'All',
    [string]$export = ''
)

$admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
$filename = 'results.html'
$Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@

##
## Defining Functions
##

#fips bit
function Get-FipsValue {
    $fips_value = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy -Name "Enabled"
    $fips_value
}

function Export-FipsValue {
    param (
        $fips_value
    )
    $fips_value | ConvertTo-Html -Fragment -PreContent '<h2>FIPS Value</h2>' -Property PSChildName, PSPath, Enabled | Out-String
}

#dep value
function Get-DepValue {
    $dep_value = wmic os get dataexecutionprevention_supportpolicy
    $dep_value = $dep_value[2] -replace '\s',''
    $dep_value = [Dep]::new($dep_value)
    $dep_value
}

class Dep {
    [int]$Value
    [string]$Property = 'Data Execution Prevention'
    Dep(
        [string]$val
    ){
        $this.Value = $val
    }

    [string]ToString(){
        return $this.Value
    }
}

function Export-DepValue {
    param (
        $dep_value
    )
    $dep_value | ConvertTo-Html -Fragment -PreContent '<h2>Data Execution Prevention Value</h2>' -Property Property, Value | Out-String
}

#bitlocker status, admin rights required
# Get-BitLockerVolume -MountPoint 'C:'


#av status
function Get-AvStatus {
#default action mapping is (starting at 0) - Clean, Quarantine, Remove, Allow, UserDefined, NoAction, Block
#day schedule mapping: 0: Everyday 1: Sunday 2: Monday 3: Tuesday 4: Wednesday 5: Thursday 6: Friday 7: Saturday 8: Never
#time is hours after midnight local computer time
    $av_status = Get-MpComputerStatus | Select-Object -Property AntivirusEnabled, AntivirusSignatureLastUpdated, FullScanAge, QuickScanAge, RealTimeProtectionEnabled    
    $av_status
}

function Export-AvStatus {
    param (
        $av_status
    )
    $av_status | ConvertTo-Html -Fragment -PreContent '<h2>AV Status</h2>' | Out-String
}

function Get-AvPreferences {
    $av_preferences = Get-MpPreference
    $av_preferences
}

function Export-AvPreferences {
    param (
        $av_preferences
    )
    $av_preferences | ConvertTo-Html -Fragment -PreContent '<h2>AV Preferences</h2>' -Property CheckForSignaturesBeforeRunningScan, HighThreatDefaultAction, LowThreatDefaultAction, ScanScheduleDay, ScanScheduleTime, ScanScheduleQuickScanTime | Out-String
}

#dns + ipconfig
function Get-NetworkInfo {
    $network_configuration = Get-NetIPConfiguration
    $network_configuration
}

function Export-NetworkInfo {
    param (
        $network_info
    )
    $network_info | ConvertTo-Html -Fragment -PreContent '<h2>Network Info</h2>' -Property ComputerName, InterfaceAlias | Out-String
}

#tls cipher suites
function Get-Ciphers {
    $ciphers = Get-TlsCipherSuite | Select-Object $_.name
    $ciphers 
}

function Export-Ciphers {
    param (
        $ciphers
    )
    $ciphers | ConvertTo-Html -Fragment -PreContent '<h2>Ciphers</h2>' -Property Name | Out-String
}

#local users
function Get-LocalUserInfo {
    $users = Get-LocalUser
    $user_information = $users | ForEach-Object -Process {Get-LocalUser $_.name | Select-Object name, Enabled, PasswordExpires, PasswordLastSet, LastLogon, PrincipalSource}
    $user_information
}

function Export-LocalUserInfo {
    param (
        $user_info
    )
    $user_info | ConvertTo-Html -Fragment -PreContent '<h2>Local User Information</h2>' | Out-String
}

#password policy TODO
# requires server role, does not work on w10.

# auditable events
# requires admin priv
function Get-AuditableEvents {
    $auditable_events = auditpol.exe /get /category:*
    # Write-Host $auditable_events
    # $auditable_events_object = [AuditableEvents]::new('')
    # $auditable_events_object.Value = $auditable_events
    $auditable_event_array = New-Object System.Collections.ArrayList
    foreach ($line in $auditable_events) {
        if ($line) {
            Write-Host $line
            $new_event_type = [AuditableEvents]::new($line)
            $auditable_event_array.Add($new_event_type)
        }

        # $auditable_events_object.Value = $auditable_events_object.Value + '  ' + $line
        # write-host $line.ToString()

    }
    $auditable_event_array
}

class AuditableEvents {
    [string]$Value
    [string]$Property = 'Auditable Events'
    AuditableEvents(
        [string]$val
    ){
        $this.Value = $val
    }
    
    [string]ToString(){
        return $this.Value
    }
}


function Export-AuditableEvents {
    param (
        $events
    )
    $events | ConvertTo-Html -Fragment -PreContent '<h2>Auditable Events</h2>' | Out-String
}

#windows patch status
#need to test this more
function Get-UpdateLastInstallDate {
    $last_installed_update = (New-Object -com "Microsoft.Update.AutoUpdate").Results
    $last_installed_update
}

function Export-UpdateLastInstallDate {
    param (
        $last_install_date
    )
    $last_install_date | ConvertTo-Html -Fragment -PreContent '<h2>Last Update Install Date' | Out-String
}

# #odl running TODO: get the proper name of the service. 
function Get-OdlStatus {
    $odl = Get-Service -Name 'Name'
    $odl_status = $odl.Status
    $odl_status
}


#applocker status/config
# requires admin priv
function Get-AppLockerInfo {
    $applocker = Get-AppLockerPolicy -Effective
    $applocker
}

function Export-AppLockerInfo {
    param (
        $applocker
    )
    $applocker | ConvertTo-Html -Fragment -PreContent '<h2>AppLocker Effective Policy</h2>' | Out-String
}


#windows status and rules firewall TODO

#schannel? Do we need this? TODO


##
## Calling functions and exporting data to html report. 
##

if ($controls -eq 'All' -and $admin -eq $false ) {
    Write-Host 'Running in non-admin mode'
    #do stuff that doesnt need admin rights
    $dep_report = Export-DepValue(Get-DepValue)
    $fips_report = Export-FipsValue(Get-FipsValue)
    $av_status_report = Export-AVStatus(Get-AvStatus)
    $av_pref_report = Export-AvPreferences(Get-AvPreferences)
    $network_report = Export-NetworkInfo(Get-NetworkInfo)
    $cipher_report = Export-Ciphers(Get-Ciphers)
    $local_user_report = Export-LocalUserInfo(Get-LocalUserInfo)
    ConvertTo-Html -head $Header -PostContent $fips_report, $dep_report, $av_status_report, $av_pref_report, $network_report, $cipher_report, $local_user_report | Out-File -FilePath $filename
}
elseif ($controls -eq 'All' -and $admin -eq $true) {
    Write-Host 'Running in admin mode'
    $dep_report = Export-DepValue(Get-DepValue)
    $fips_report = Export-FipsValue(Get-FipsValue)
    $av_status_report = Export-AVStatus(Get-AvStatus)
    $av_pref_report = Export-AvPreferences(Get-AvPreferences)
    $network_report = Export-NetworkInfo(Get-NetworkInfo)
    $cipher_report = Export-Ciphers(Get-Ciphers)
    $local_user_report = Export-LocalUserInfo(Get-LocalUserInfo)
    # do stuff that needs admin rights 
    $auditable_events_report = Export-AuditableEvents(Get-AuditableEvents)
    $update_report = Export-UpdateLastInstallDate(Get-UpdateLastInstallDate)
    $applocker_report = Export-AppLockerInfo(Get-AppLockerInfo)
    ConvertTo-Html -head $Header -PostContent $fips_report, $dep_report, $av_status_report, $av_pref_report, $network_report, $cipher_report, $local_user_report, $auditable_events_report, $update_report, $applocker_report | Out-File -FilePath $filename
}
elseif ($controls -ne 'All' -and $admin -eq $true) {
    Write-Host '3'
}
elseif ($controls -ne 'All' -and $admin -eq $false) {
    Write-Host '4'
}
