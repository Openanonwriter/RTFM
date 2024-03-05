Write-Host "Welcome to RTFM's SYSTEM INFO" -ForegroundColor RED
Write-Host "Widnows" -ForegroundColor Magenta
$osname = (Get-WmiObject -class Win32_OperatingSystem).Caption
$osversion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')
Write-Host "$osname $osversion"
#Uptime
$os = Get-WmiObject -Class Win32_OperatingSystem
$lastBootUpTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
$uptime = (Get-Date) - $lastBootUpTime
$days = [math]::floor($uptime.TotalDays)
$hours = $uptime.Hours
Write-Output ("Uptime: {0} Days {1} Hours" -f $days, $hours)

Write-Host ""
Write-Host "Motherboard" -ForegroundColor Magenta
Get-WmiObject -Class Win32_BaseBoard | Format-Table Manufacturer, Product, SerialNumber, Version -Auto

Write-Host ""
Write-Host "RAM" -ForegroundColor Magenta
$ramInfo = Get-WmiObject -Class Win32_PhysicalMemory
$numberOfSlots = ($ramInfo | Select-Object -Property BankLabel | Get-Unique).Count
$ramType = $ramInfo.SMBIOSMemoryType

$ramTypePrinted = $false

switch ($ramType) {
    0 { if (-not $ramTypePrinted) { Write-Host "RAM Type: Unknown"; $ramTypePrinted = $true } }
    1 { if (-not $ramTypePrinted) { Write-Host "RAM Type: Other"; $ramTypePrinted = $true } }
    20 { if (-not $ramTypePrinted) { Write-Host "RAM Type: DDR"; $ramTypePrinted = $true } }
    21 { if (-not $ramTypePrinted) { Write-Host "RAM Type: DDR2"; $ramTypePrinted = $true } }
    22 { if (-not $ramTypePrinted) { Write-Host "RAM Type: DDR2 FB-DIMM"; $ramTypePrinted = $true } }
    24 { if (-not $ramTypePrinted) { Write-Host "RAM Type: DDR3"; $ramTypePrinted = $true } }
    26 { if (-not $ramTypePrinted) { Write-Host "RAM Type: DDR4"; $ramTypePrinted = $true } }
    default { Write-Host "RAM Type: Unknown" }
}

if ($ramTypePrinted) {
    Write-Host "Number of RAM slots: $numberOfSlots"
}

Write-Host "Number of RAM Slots Filled: $($numberOfSlots + 1)"

$totalRAMSizeGB = ($ramInfo | Measure-Object -Property Capacity -Sum).Sum / 1GB
Write-Host "Total RAM Size: $totalRAMSizeGB GB"

wmic memorychip get banklabel, manufacturer, partnumber, speed, MemoryType, SMBIOSMemoryType, devicelocator

Write-Host ""
Write-Host "CPU" -ForegroundColor Magenta
$cpuInfo = Get-WmiObject -Class Win32_Processor
Write-Host "Socket: $($cpuInfo.SocketDesignation)"
Write-Host "# of Sockets: $((Get-WmiObject -Class Win32_ComputerSystem).NumberOfProcessors)"
Write-Host "Name: $($cpuInfo.Name)"
Write-Host "# of Cores: $($cpuInfo.NumberOfCores)"
Write-Host "# of Threads: $($cpuInfo.NumberOfLogicalProcessors)"
Write-Host "Max Clock Speed: $($cpuInfo.MaxClockSpeed) Mhz"
Write-Host ""

#Network
Write-Host ""
Write-Host "Network" -ForegroundColor Magenta
$hostname = [System.Net.Dns]::GetHostName()
Write-Host "Hostname: $hostname"
$winrmStatus = Get-WmiObject -Class Win32_Service -Filter "Name = 'winrm'"
if ($winrmStatus.State -eq "Running") {
    Write-Host "WinRM: Enabled"
} else {
    Write-Host "WinRM: Disabled"
}
# External IP
$externalIp = nslookup myip.opendns.com resolver1.opendns.com | findstr /R /C:"Address: .*" | select -last 1
$externalIp = $externalIp -replace "Address: ",""
Write-Host "External IP: " -NoNewline 
Write-Host $externalIp -ForegroundColor YELLOW

$networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'"

foreach ($adapter in $networkAdapters) {
    Write-Host "Network Adapter: $($adapter.Description)"
    Write-Host "Physical Address (MAC): $($adapter.MACAddress)"
    Write-Host "DHCP Enabled: $($adapter.DHCPEnabled)"
    Write-Host "IPv4 Address: $($adapter.IPAddress -join ', ')"
    Write-Host "IPv4 Subnet Mask: $($adapter.IPSubnet -join ', ')"
    Write-Host "IPv4 Default Gateway: $($adapter.DefaultIPGateway -join ', ')"
    Write-Host "IPv4 DNS Servers: $($adapter.DNSServerSearchOrder -join ', ')"
    Write-Host "NetBIOS over Tcpip: $($adapter.WINSPrimaryServer -ne $null)"
    Write-Host "IPv6 Enabled: $($adapter.IPv6Enabled)"
    Write-Host
}
# Firewall 
Write-Host "Firewall"-ForegroundColor Magenta
Get-NetFirewallProfile | Format-Table Name, Enabled

#Anti-Virus
write-host "Active Anti-Virus"-ForegroundColor Magenta
function Get-AntiVirusProduct {
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('name')]
        $computername = $env:computername
    )

    $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ComputerName $computername
    $ret = @()

    foreach ($AntiVirusProduct in $AntiVirusProducts) {
        # Switch to determine the status of antivirus definitions and real-time protection
        # You can customize this part as needed
        $status = if ($AntiVirusProduct.productupdaterequired) { "Out of date" } else { "Up to date" }
        $realTimeProtection = if ($AntiVirusProduct.productupdaterequired) { "Disabled" } else { "Enabled" }

        $ret += @{
            ComputerName = $computername
            ProductName = $AntiVirusProduct.displayName
            DefinitionStatus = $status
            RealTimeProtection = $realTimeProtection
        }
    }

    $ret
}
Get-AntiVirusProduct | Out-String

#AV's Installed in registry
Write-Host "Checking Anti-Virus found in Registry..."
$antivirusNames = @(
    "Avast",
    "AVG",
    "Avira",
    "Bitdefender",
    "ZoneAlarm",
    "Immunet",
    "ClamWin",
    "Comodo",
    "Dr.Web",
    "ESET",
    "F-Secure",
    "G DATA",
    "Kaspersky",
    "Malwarebytes",
    "McAfee",
    "Windows Defender",
    "NANO",
    "Norton",
    "Spyware",
    "Panda",
    "360 Total Security",
    "Sophos",
    "Titanium",
    "TrustPort",
    "Vba32",
    "Viper",
    "Sentinel",
    "Webroot"
)

foreach ($antivirusName in $antivirusNames) {
    $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $subKeys = Get-ChildItem -Path $keyPath

    foreach ($subKey in $subKeys) {
        $displayName = (Get-ItemProperty -Path "$keyPath\$($subKey.PSChildName)" -ErrorAction SilentlyContinue).DisplayName
        if ($displayName -like "*$antivirusName*") {
            Write-Host "$antivirusName is also installed."
            break
        }
    }
}

Write-Host "Checking for Antivirus Programs in Program Files..."

$antivirusPrograms = @(
    "Avast",
    "AVG",
    "Avira",
    "Bitdefender",
    "ZoneAlarm",
    "Immunet",
    "ClamWin",
    "Comodo",
    "Dr.Web",
    "ESET",
    "F-Secure",
    "G DATA",
    "Kaspersky",
    "Malwarebytes",
    "McAfee",
    "Windows Defender",
    "NANO",
    "Norton",
    "Spyware",
    "Panda",
    "360 Total Security",
    "Sophos",
    "Titanium",
    "TrustPort",
    "Vba32",
    "Viper",
    "Sentinel",
    "Webroot"
)

$programFiles = [System.Environment]::GetFolderPath('ProgramFiles')
$programFilesx86 = [System.Environment]::GetFolderPath('ProgramFilesX86')

foreach ($programName in $antivirusPrograms) {
    if (Test-Path -Path "$programFiles\$programName") {
        Write-Host "$programName found in Program Files"
    }
    if (Test-Path -Path "$programFilesx86\$programName") {
        Write-Host "$programName found in Program Files (x86)"
    }
}

Write-Host "Diagnostic Data" -ForegroundColor Magenta
$miniDumpPath = "C:\Windows\Minidump"
$miniDumpCount = (Get-ChildItem -Path $miniDumpPath -File -ErrorAction SilentlyContinue).Count
# Mini Dumps
if ($miniDumpCount -gt 0) {
    Write-Host "Mini-Dumps found: " -NoNewline 
    Write-Host "$miniDumpCount" -ForegroundColor Red
} else {
    Write-Host "Mini-Dumps found: 0"
}

# Windows Updates
Write-Host "Windows Updates" -ForegroundColor Magenta
# Create a session to interact with Windows Update
$UpdateSession = New-Object -ComObject "Microsoft.Update.Session"
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

# Search for updates that are not yet installed
$SearchResult = $UpdateSearcher.Search('IsInstalled=0')

# Filter updates by severity
$critical = $SearchResult.updates | Where-Object { $_.MsrcSeverity -eq "Critical" }
$important = $SearchResult.updates | Where-Object { $_.MsrcSeverity -eq "Important" }
$optional = $SearchResult.updates | Where-Object { ($_.MsrcSeverity -ne "Critical") -and ($_.MsrcSeverity -ne "Important") }

# Calculate total updates
$totalUpdates = $critical.Count + $important.Count + $optional.Count

# Display the counts
Write-Host "Critical Count: $($critical.Count)"
Write-Host "Important Count: $($important.Count)"
Write-Host "Optional Count: $($optional.Count)"
Write-Host "Total Updates: $totalUpdates"

Write-Host "Remote Desktop Applications" -ForegroundColor Magenta
# Check if any remote desktop apps are installed, in the registry
Write-Host "Checking for Remotedesktop programs found in registry..."
$remoteAccessPrograms = @(
    "TeamViewer",
    "AnyDesk",
    "Chrome Remote Desktop",
    "Microsoft Remote Desktop",
    "UltraVNC",
    "RealVNC",
    "LogMeIn",
    "GoToMyPC",
    "Zoho Assist",
    "Splashtop",
    "Remote Utilities",
    "Ammyy Admin",
    "ShowMyPC",
    "Radmin",
    "NoMachine",
    "ConnectWise Control",
    "Dameware Remote Everywhere",
    "Parallels Access",
    "RemotePC",
    "Zoho Assist"
)

foreach ($programName in $remoteAccessPrograms) {
    $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $subKeys = Get-ChildItem -Path $keyPath

    foreach ($subKey in $subKeys) {
        $displayName = (Get-ItemProperty -Path "$keyPath\$($subKey.PSChildName)" -ErrorAction SilentlyContinue).DisplayName
        if ($displayName -like "*$programName*") {
            Write-Host "$programName is installed."
            break
        }
    }
}

Write-Host "Checking for Remote Access Programs in Program Files..."

$remoteAccessPrograms = @(
    "TeamViewer",
    "AnyDesk",
    "Chrome Remote Desktop",
    "Microsoft Remote Desktop",
    "UltraVNC",
    "RealVNC",
    "LogMeIn",
    "GoToMyPC",
    "Zoho Assist",
    "Splashtop",
    "Remote Utilities",
    "Ammyy Admin",
    "ShowMyPC",
    "Radmin",
    "NoMachine",
    "ConnectWise Control",
    "Dameware Remote Everywhere",
    "Parallels Access",
    "RemotePC",
    "Zoho Assist"
)

$programFiles = [System.Environment]::GetFolderPath('ProgramFiles')
$programFilesx86 = [System.Environment]::GetFolderPath('ProgramFilesX86')

foreach ($programName in $remoteAccessPrograms) {
    if (Test-Path -Path "$programFiles\$programName") {
        Write-Host "$programName found in Program Files"
    }
    if (Test-Path -Path "$programFilesx86\$programName") {
        Write-Host "$programName found in Program Files (x86)"
    }
}

$TermServ = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\CIMv2\TerminalServices
$RDPStatus = $TermServ.GetAllowTSConnections
if ($RDPStatus.ReturnValue -eq 0) {
    Write-Host "Windows Remote Desktop: Enabled."
} else {
    Write-Host "Windows Remote Desktop: Disabled."
}




Read-Host -Prompt "Press CTL ^ C to Exit"
Start-Sleep -Seconds 120