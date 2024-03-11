#Writen By Anthony Widick

# Upgrade to admistrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated permissions
    Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
function Show-Menu {
    param (
        [string]$Title = 'My Menu'
    )
	clear-host

function Write-HostCenter-Magenta {
    param($Message)
    Write-Host ("{0}{1}" -f (' ' * (([Math]::Max(0, $Host.UI.RawUI.BufferSize.Width / 2) - [Math]::Floor($Message.Length / 2)))), $Message) -ForegroundColor Magenta
}
function Write-HostCenter {
    param($Message)
    Write-Host ("{0}{1}" -f (' ' * (([Math]::Max(0, $Host.UI.RawUI.BufferSize.Width / 2) - [Math]::Floor($Message.Length / 2)))), $Message) 
}

Write-HostCenter-Magenta "Welcome to RTFM's SYSTEM INFO" 
Write-HostCenter-Magenta "=============================" 
Write-HostCenter "This script is intended for initial screening only, and does not provide definitive information."
Write-HostCenter "Please verify the results manually if you encounter any discrepancies."

Write-Host "Widnows Quick Info" -ForegroundColor Magenta
$osname = (Get-WmiObject -class Win32_OperatingSystem).Caption
$osversion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')
Write-Host "$osname $osversion"

# Get system uptime 
$os = Get-WmiObject -Class Win32_OperatingSystem
$lastBootUpTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
$uptime = (Get-Date) - $lastBootUpTime
$days = [math]::floor($uptime.TotalDays)
$hours = $uptime.Hours
$minutes = $uptime.Minutes

Write-Output ("Uptime: {0} Days {1} Hours {2} Minutes" -f $days, $hours, $minutes)


# Get the system boot Date
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

# Get and display the Windows activation status
$WinVerAct = (cscript /Nologo "C:\Windows\System32\slmgr.vbs" /dlv) -join ''
$activationStatus = if ($WinVerAct -match 'Licensed') {
    'Licensed'
} elseif ($WinVerAct -match 'Out-of-Box') {
    'Out-of-Box (OOB)'
} elseif ($WinVerAct -match 'Non-Genuine Grace') {
    'Non-Genuine Grace'
} elseif ($WinVerAct -match 'Out of Tolerance Grace') {
    'Out of Tolerance (OOT) Grace'
} elseif ($WinVerAct -match 'Unlicensed') {
    'Unlicensed'
} elseif ($WinVerAct -match 'Notification') {
    'Notification'
} elseif ($WinVerAct -match 'Extended Grace') {
    'Extended Grace'
} else {
    'Unknown'
}

# Initialize the license type
$licenseType = "Unknown"

# Check for different product key channels
if ($WinVerAct -match 'Product Key Channel: STA') {
    $licenseType = 'Static Activation Key (STA)'
} elseif ($WinVerAct -match 'Product Key Channel: OEM') {
    $licenseType = 'OEM (Original Equipment Manufacturer)'
} elseif ($WinVerAct -match 'Product Key Channel: Retail') {
    $licenseType = 'Retail (FPP, Boxed Copy)'
} elseif ($WinVerAct -match 'Product Key Channel: VL1') {
    $licenseType = 'Volume License (VL1)'
} elseif ($WinVerAct -match 'Product Key Channel: FPP') {
    $licenseType = 'Retail (Full Packaged Product)'
}

#Write-Host "Windows activation status: $activationStatus"

if ($activationStatus -eq "Licensed") {
    Write-Host "Windows activation status: " -NoNewline
    Write-Host "$activationStatus" -ForegroundColor Green
}
else {
    Write-Host "Windows activation status: " -NoNewline
    Write-Host "$activationStatus"-ForegroundColor Red
}



Write-Host "Windows key type: $licenseType"



# Check if the Windows license type is Retail, OEM, or Volume
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
$keyName = "BackupProductKeyDefault"

# Check if the registry path exists
if (Test-Path $registryPath) {
    try {
        # Get the key's value 
        $keyValue = (Get-ItemProperty -Path $registryPath -Name $keyName).$keyName

        # If the value exists, print it
        if ($keyValue) {
            Write-Host "Registered Product Key: " -NoNewline
            Write-Host "$keyValue" -BackgroundColor Black -ForegroundColor Red
        } else {
            Write-Warning "Value '$keyName' was not found."
        }
    } catch {
        # Handle potential errors during retrieval 
        Write-Host "Error retrieving the value: $($_.Exception.Message)"
    }
} else {
    Write-Host "Registry path '$registryPath' does not exist."
}

Write-Host ""
    Write-Host "================ $Title ================"
    Write-Host "(Hardware) Info"
    Write-Host "(Network) Info"
    Write-Host "(App)s Info"
    Write-Host "(Windows) Info"
    Write-Host "(6)Install Anydesk, Malwarebytes, AdobeReader, Chrome"
    Write-Host "(Repair) Windows"
    Write-Host "(Q)uit"
}

while ($true) {
    Show-Menu -Title 'RTFM Main Menu'
    $selection = Read-Host "Please make a selection"

    switch ($selection) {
        'Hardware' { 
			Clear-Host
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
			
			# Get information about physical memory
			$MemorySlots = Get-WmiObject Win32_PhysicalMemory | Where-Object { $_.Capacity -gt 0 }
			$PopulatedSlotCount = $MemorySlots.Count
			
			# Display the result
			"Total populated DIMM slots: $PopulatedSlotCount"
			
			"Total DIMM SLOTS: $((Get-WmiObject -Class 'Win32_PhysicalMemoryArray').MemoryDevices)"
			
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
			
			Write-Host "CPU" -ForegroundColor Magenta
			$cpuInfo = Get-WmiObject -Class Win32_Processor
			Write-Host "Name: $($cpuInfo.Name)"
			Write-Host "Socket: $($cpuInfo.SocketDesignation)"
			Write-Host "# of Sockets: $((Get-WmiObject -Class Win32_ComputerSystem).NumberOfProcessors)"
			Write-Host "# of Cores: $($cpuInfo.NumberOfCores)"
			Write-Host "# of Threads: $($cpuInfo.NumberOfLogicalProcessors)"
			Write-Host "Max Clock Speed: $($cpuInfo.MaxClockSpeed) Mhz"
		
            Write-Host ""
            Write-Host "----------END----------"
            Read-Host}
      #Network      
'Network' { 
            Clear-Host
Write-Host ""
Write-Host "Network" -ForegroundColor Magenta
$hostname = [System.Net.Dns]::GetHostName()
Write-Host "Hostname: $hostname"


# External IP
$externalIp = $null

# Try ipinfo.io first
try {
    $externalIp = (Invoke-RestMethod -Uri 'https://ipinfo.io/json').ip
    Write-Host "External IP IPINFO: " -NoNewline
    Write-Host $externalIp -ForegroundColor Yellow
}
catch {
    Write-Host "Failed to retrieve IP from ipinfo.io. Trying checkip.amazonaws.com..." -ForegroundColor Red
}

# If ipinfo.io fails, try checkip.amazonaws.com
if (-not $externalIp) {
    try {
        $externalIp = (Invoke-RestMethod -Uri 'https://checkip.amazonaws.com/').Trim()
        Write-Host "External IP AMAZONAWS: " -NoNewline
        Write-Host $externalIp -ForegroundColor Yellow
    }
    catch {
        Write-Host "Failed to retrieve IP from checkip.amazonaws.com as well." -ForegroundColor Red
    }
}



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
Write-Host ""
Write-Host "----------END----------"
Read-Host

         }
        'App' { 


Clear-Host
#Check if any remote desktop apps are installed, in the registry
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
        Write-Host "$programName" -NoNewline -ForegroundColor Green
        Write-Host " found in Program Files"
    }
    if (Test-Path -Path "$programFilesx86\$programName") {
        Write-Host "$programName" -NoNewline -ForegroundColor Green
        Write-Host " found in Program Files (x86)"
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
    "FortiClient VPN"
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
Write-Host ""
Write-Host "----------END----------"
Read-Host

         }
        '4' { Write-Host "AV" }
        '5' { Write-Host "You chose Option 5" }
        '6' { 

            # Check if an application is installed
            function Is-AppInstalled($appId) {
            $installedApps = winget list
            return $installedApps -match $appId
            }

# Install or update an application
        function InstallOrUpdate-App($appId) {
            if (Is-AppInstalled $appId) {
                Write-Host "Updating $appId..."
                winget upgrade --id $appId
            } else {
                Write-Host "Installing $appId..."
                winget install --exact --id $appId
            }
        }

            # Check and install/update applications
            InstallOrUpdate-App "Malwarebytes.Malwarebytes"
            InstallOrUpdate-App "Adobe.Acrobat.Reader.64-bit"
            InstallOrUpdate-App "Google.Chrome"
            InstallOrUpdate-App "AnyDeskSoftwareGmbH.AnyDesk"
            Read-Host
# End of Menu 6
}
        'repair' {
            Clear-Host
# Powershell script to run sfc first, then run dism if sfc shows "Windows Resource Protection found corrupt files and successfully repaired them.", then sfc a second time.

# Run sfc first and capture output
Write-Host "Running sfc.exe..."
$sfcOutput = sfc.exe /scannow 2>&1 | ForEach-Object { Write-Host $_; $_ } | Tee-Object -Variable sfcResults

# Check if sfc reported successful repair
if ($sfcOutput -match "Windows Resource Protection found corrupt files and successfully repaired them.") {
    Write-Host "SFC detected and repaired corrupt files. Running DISM..."

    # Run DISM
    dism.exe /online /cleanup-image /restorehealth 2>&1 | ForEach-Object { Write-Host $_; $_ } | Tee-Object -Variable dismResults

    Write-Host "DISM completed. Running sfc again..."

    # Run sfc again
    sfc.exe /scannow 2>&1 | ForEach-Object { Write-Host $_; $_ } | Tee-Object -Variable sfcResults
}

Write-Host "DISM and SFC completed" -ForegroundColor Magenta

Write-Host ""
Write-Host "----------END----------"
Read-Hostt}

 'Windows'{
Clear-Host

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
 
Write-Host ""
Write-Host "----------END----------"
Read-Host}
#End of Top Menu
        'iperf' {
                # Prompt the user for IPerf3 arguments
                $iperfArgs = Read-Host "Enter IPerf3 Args"

                # Run IPerf3 with the provided arguments
                Start-Process -FilePath .\iperf3.exe -ArgumentList $iperfArgs
        Read-Host}
        'ALL' { Write-Host "ALL" }
        'q' { exit }
        default { Write-Host "Invalid selection. Please choose again." }
    }
}
