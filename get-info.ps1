Write-Host "Welcome to RTFM's SYSTEM INFO" -ForegroundColor RED
Write-Host "This script is intended for initial screening only, and does not provide definitive information. Please verify the results manually if you encounter any discrepancies." -ForegroundColor RED

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

# Get the system boot time
$bootTime = $os.LastBootUpTime.Substring(0,8)
$bootYear = $bootTime.Substring(0,4)
$bootMonth = $bootTime.Substring(4,2)
$bootDay = $bootTime.Substring(6,2)
Write-Host "System Boot Time: $bootMonth/$bootDay/$bootYear"

# Get the original install date
$os = Get-WmiObject -Class Win32_OperatingSystem
$installDate = $os.InstallDate.Substring(0,8)
$installYear = $installDate.Substring(0,4)
$installMonth = $installDate.Substring(4,2)
$installDay = $installDate.Substring(6,2)
Write-Host "Original Install Date: $installMonth/$installDay/$installYear"

Write-Host "Motherboard" -ForegroundColor Magenta
Get-WmiObject -Class Win32_BaseBoard | Format-Table Manufacturer, Product, SerialNumber, Version -Auto

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

# Create an empty array to store the output
$memoryChipInfo = @()

# Get WMI objects for memory chips
$memoryChips = Get-WmiObject -Class Win32_PhysicalMemory

# Loop through each memory chip
foreach ($chip in $memoryChips) {
    # Create a custom object for each chip with the properties you want
    $chipInfo = New-Object PSObject -Property @{
        BankLabel = $chip.BankLabel
        Manufacturer = $chip.Manufacturer
        PartNumber = $chip.PartNumber
        Speed = $chip.Speed
        MemoryType = $chip.MemoryType
        SMBIOSMemoryType = $chip.SMBIOSMemoryType
        DeviceLocator = $chip.DeviceLocator
    }

    # Add the custom object to the array
    $memoryChipInfo += $chipInfo
}

# Output the array
$memoryChipInfo | Format-Table

Write-Host ""
Write-Host "CPU" -ForegroundColor Magenta
$cpuInfo = Get-WmiObject -Class Win32_Processor
Write-Host "Name: $($cpuInfo.Name)"
Write-Host "Socket: $($cpuInfo.SocketDesignation)"
Write-Host "# of Sockets: $((Get-WmiObject -Class Win32_ComputerSystem).NumberOfProcessors)"
Write-Host "# of Cores: $($cpuInfo.NumberOfCores)"
Write-Host "# of Threads: $($cpuInfo.NumberOfLogicalProcessors)"
Write-Host "Max Clock Speed: $($cpuInfo.MaxClockSpeed) Mhz"
Write-Host ""

#Network
Write-Host ""
Write-Host "Network" -ForegroundColor Magenta
$hostname = [System.Net.Dns]::GetHostName()
Write-Host "Hostname: $hostname"

# External IP
$externalIp = nslookup myip.opendns.com resolver1.opendns.com | findstr /R /C:"Address: .*" | select -last 1
$externalIp = $externalIp -replace "Address: ",""
Write-Host "External IP NSLOOKUP METHOD: " -NoNewline 
Write-Host $externalIp -ForegroundColor YELLOW

# External IP
$externalIp = (Invoke-RestMethod -Uri 'https://ipinfo.io/json').ip
Write-Host "External IP IPINFO: " -NoNewline 
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

#AV's Installed
Write-Host "Antivirus Applications" -ForegroundColor Magenta

# List of antivirus apps to check
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

# Check if any antivirus apps are installed, in the registry
Write-Host "Checking for Antivirus programs found in registry..."
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$subKeys = Get-ChildItem -Path $keyPath

foreach ($antivirusName in $antivirusNames) {
    foreach ($subKey in $subKeys) {
        $displayName = (Get-ItemProperty -Path "$keyPath\$($subKey.PSChildName)" -ErrorAction SilentlyContinue).DisplayName
        if ($displayName -like "*$antivirusName*") {
            # Print the name and the registry path of the software
            # Use -ForegroundColor Blue to print the keys in blue
            Write-Host "$antivirusName." -ForegroundColor Green -NoNewline
			Write-Host " is installed at ." -NoNewline
			Write-Host "$($subKey.PSPath)." -ForegroundColor Blue
            break
        }
    }
}

# Check if any antivirus apps are installed, in the Program Files directories
Write-Host "Checking for Antivirus Programs in Program Files..."
$programFiles = [System.Environment]::GetFolderPath('ProgramFiles')
$programFilesx86 = [System.Environment]::GetFolderPath('ProgramFilesX86')

foreach ($antivirusName in $antivirusNames) {
    if (Test-Path -Path "$programFiles\$antivirusName") {
        Write-Host "$antivirusName" -ForegroundColor Green -NoNewline
		Write-Host " found in Program Files" 
    }
    if (Test-Path -Path "$programFilesx86\$antivirusName") {
        Write-Host "$antivirusName" -ForegroundColor Green -NoNewline
		Write-Host " found in Program Files (x86)" 
    }
}


# Diagnostic data
Write-Host "Diagnostic Data" -ForegroundColor Magenta
$miniDumpPath = "C:\Windows\Minidump"
$miniDumps = Get-ChildItem -Path $miniDumpPath -Filter "*.dmp" -File -ErrorAction SilentlyContinue

# Mini Dumps
if ($miniDumps.Count -gt 0) {
    Write-Host "Mini-Dumps found: " -NoNewline 
    Write-Host "$($miniDumps.Count)" -ForegroundColor Red

    foreach ($dump in $miniDumps) {
        Write-Host "File: $($dump.Name)"
        Write-Host "Date: $($dump.LastWriteTime)"
    }
} else {
    Write-Host "Mini-Dumps found: 0"
}

# Get the CBS.log file
$cbslog = Get-Content -Path "$env:windir\Logs\CBS\CBS.log"
# Find the last line that contains the string "[SR]"
$lastSfcLine = $cbslog | Select-String -Pattern "[SR]" | Select-Object -Last 1
# Get the date and time from the last line
$lastSfcDate = $lastSfcLine.Line.Substring(0, 19)
# Write the date and time to the console
Write-Host "The last time SFC was ran was $lastSfcDate."

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




Write-Host "Remote Accesss" -ForegroundColor Magenta
# WinRM
$winrmStatus = Get-WmiObject -Class Win32_Service -Filter "Name = 'winrm'"
if ($winrmStatus.State -eq "Running") {
    Write-Host "WinRM: Enabled"
} else {
    Write-Host "WinRM: Disabled"
}

# Windows Remote Desktop
$TermServ = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\CIMv2\TerminalServices
$RDPStatus = $TermServ.GetAllowTSConnections
if ($RDPStatus.ReturnValue -eq 0) {
    Write-Host "Windows Remote Desktop: Enabled."
} else {
    Write-Host "Windows Remote Desktop: Disabled."
}

#Open-SSH
# Check if OpenSSH Server is installed
$sshServerInstalled = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

if ($sshServerInstalled) {
    Write-Host "OpenSSH Server is installed."
    
    # Check if OpenSSH SSH Server service is running
    $sshServiceStatus = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($sshServiceStatus.Status -eq 'Running') {
        Write-Host "OpenSSH SSH Server: RUNNING."
    } else {
        Write-Host "OpenSSH SSH Server: INSTALLED."
    }
} else {
    Write-Host "OpenSSH Server: Not Intalled."
}

# Check if any remote desktop apps are installed, in the registry
Write-Host "Checking for Remote Desktop programs found in registry..."

# Registry keys to search
$registryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

# List of remote desktop programs to check
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
    "Zoho Assist",
    "Bomgar",
    "Citrix GoToAssist",
    "Cisco WebEx",
    "Join.me",
    "ScreenConnect",
    "Apple Remote Desktop",
    "Microsoft Intune",
    "SolarWinds MSP Anywhere",
    "SysAid"
)

foreach ($keyPath in $registryKeys) {
    $subKeys = Get-ChildItem -Path $keyPath
    foreach ($programName in $remoteAccessPrograms) {
        foreach ($subKey in $subKeys) {
            $displayName = (Get-ItemProperty -Path "$keyPath\$($subKey.PSChildName)" -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -like "*$programName*") {
                Write-Host "$programName" -ForegroundColor Green -NoNewline
                Write-Host " is installed. (Registry Location: $($subKey.PSPath))"
                break
            }
        }
    }
}


# Check if any remote desktop apps are installed, in the Program Files directories
Write-Host "Checking for Remote Access Programs in Program Files..."

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

Write-Host "VPN Applications" -ForegroundColor Magenta

# Registry keys to search
$registryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

# List of VPN apps to check
$vpnNames = @(
    "ExpressVPN",
    "NordVPN",
    "CyberGhost",
    "IPVanish",
    "Private Internet Access",
    "Hotspot Shield",
    "Windscribe",
    "TunnelBear",
    "VyprVPN",
    "Surfshark",
    "ProtonVPN",
    "HideMyAss",
    "TorGuard",
    "Astrill",
    "Mullvad",
    "IVPN",
    "PrivateVPN",
    "PureVPN",
    "SaferVPN",
    "ZenMate",
    "StrongVPN",
    "AirVPN",
    "CactusVPN",
    "FastestVPN",
    "FrootVPN",
    "GooseVPN",
    "Hide.me",
    "iPredator",
    "IronSocket",
    "KeepSolid VPN Unlimited",
    "LiquidVPN",
    "Norton Secure VPN",
    "Perfect Privacy",
    "VPN.ht",
    "VPNArea",
    "VPNBook"
    "WireGuard"
)
# Check Registry Keys
foreach ($keyPath in $registryKeys) {
    $subKeys = Get-ChildItem -Path $keyPath
    foreach ($vpnName in $vpnNames) {
        foreach ($subKey in $subKeys) {
            $displayName = (Get-ItemProperty -Path "$keyPath\$($subKey.PSChildName)" -ErrorAction SilentlyContinue).DisplayName
            if ($displayName -like "*$vpnName*") {
                Write-Host "$vpnName" -ForegroundColor Green -NoNewline
                Write-Host " is installed. (Registry Location: $($subKey.PSPath))"
                break
            }
        }
    }
}
# Check if any VPN apps are installed, in the Program Files directories
Write-Host "Checking for VPN Programs in Program Files..."
$programFiles = [System.Environment]::GetFolderPath('ProgramFiles')
$programFilesx86 = [System.Environment]::GetFolderPath('ProgramFilesX86')

foreach ($vpnName in $vpnNames) {
    if (Test-Path -Path "$programFiles\$vpnName") {
        Write-Host "$vpnName" -ForegroundColor Green -NoNewline
		Write-Host " found in Program Files"
    }
    if (Test-Path -Path "$programFilesx86\$vpnName") {
        Write-Host "$vpnName"-ForegroundColor Green -NoNewline
		Write-Host " found in Program Files (x86)"
    }
}







Read-Host -Prompt "Press CTL ^ C to Exit"
Start-Sleep -Seconds 120