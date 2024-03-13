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
    Write-Host "(NDT) Network Diagnostic Tool"
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
            
            #Start of Crystal Disk
            Start-Sleep -Seconds 5
            Write-Host "PHYSICAL DISK INFO provided by CrystalDisk" -ForegroundColor Magenta

            #do not need this variable, its already in rtfm later.
            $currentDirectory = $PSScriptRoot

            $cdiskinfo = Get-ChildItem -Path $currentDirectory -Filter DiskInfo64.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
            & "$cdiskinfo" /CopyExit
            $diskinfoPath = Get-ChildItem -Path $currentDirectory -Filter DiskInfo.txt -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
            $smartData = Get-Content -Path $diskinfoPath
            # Read the content of the text file (replace 'x.txt' with the actual file path)
            # Flag to indicate whether we are within the S.M.A.R.T. section
            $inSmartSection = $false
            $unneeded0 = '-- SMART_NVME --------------------------------------------------------------'
            $unneeded1 = "        0    1    2    3    4    5    6    7    8    9"
            $unneeded2 = '     \+0 \+1 \+2 \+3 \+4 \+5 \+6 \+7 \+8 \+9 \+A \+B \+C \+D \+E \+F'
            # Process each line in the file
            if ($smartData -eq 'j;lasdfja;lsdfja;lsdjfaowerfnalsdfuasodfjas;lerfijas;odlfjasdl;fj'){
            foreach ($line in $smartData) {
            # Ignore empty lines and the line with 'ID RawValues(6) Attribute Name'
            if ([string]::IsNullOrWhiteSpace($line) -or $line -match "ID RawValues\(6\) Attribute Name") {
                continue
            }

            if ($line -match "-- S.M.A.R.T. -------") {
                # Start of S.M.A.R.T. section
                $inSmartSection = $true
                Write-Host "-- S.M.A.R.T. --------------------------------------------------------------"
                Write-Host "ID RawValues(6) Attribute Name"
                continue
            }
            elseif ($line -match "-- IDENTIFY_DEVICE ------") {
                # End of S.M.A.R.T. section
                $inSmartSection = $false
                Write-Host " "
                Write-Host "----------------------------------------------------------------------------"
                # Don't break here, as there might be more S.M.A.R.T. sections
                continue
            }

            if ($inSmartSection) {
                # Extract the relevant information (ID, RawValues, and Attribute Name)
                $columns = $line -split '\s+'
                $id = $columns[0]
                $rawValue = $columns[4]
                $attributeName = $columns[5,6,7,8,7,8,9,10]
                # Convert the hexadecimal string to a decimal number using BigInteger
                $decimalValue = [System.Numerics.BigInteger]::Parse($rawValue, [System.Globalization.NumberStyles]::HexNumber)


                # Display the result
                Write-Host "$id $decimalValue           $attributeName "
                $unneeded0 = "-- SMART_NVME --------------------------------------------------------------"
                $unneeded1 = "        0    1    2    3    4    5    6    7    8    9"
                $unneeded2 = '     \+0 \+1 \+2 \+3 \+4 \+5 \+6 \+7 \+8 \+9 \+A \+B \+C \+D \+E \+F'
                $undeeded3 = '-- SMART_NVME2--------------------------------------------------------------'
            } elseif (-not ($line -match "^(000:|010:|020:|0AE:|030:|040:|050:|060:|070:|080:|090:|100:|110:|120:|130:|140:|150:|160:|170:|180:|190:|200:|210:|220:|230:|240:|250:|1A0:|0A0:|0B0:|0D0:|1B0:|1C0:|0E0:|0C0:|0F0:|1E0:|1D0:|1F0:|$shittext|$unneeded1|$unneeded2|$undeeded3)")) {        # If not in a S.M.A.R.T. section and not a filtered line, print the line
                Start-Sleep -Milliseconds 10
                Write-Host $line
            }
        }
    }
            else {
            foreach ($line in $smartData) {
                # Ignore empty lines and the line with 'ID RawValues(6) Attribute Name'
                if ([string]::IsNullOrWhiteSpace($line) -or $line -match "ID RawValues\(6\) Attribute Name") {
                    Start-Sleep 1
                    continue
                }

                if ($line -match "-- S.M.A.R.T. -------") {
                    # Start of S.M.A.R.T. section
                    $inSmartSection = $true
                    Write-Host "-- S.M.A.R.T. --------------------------------------------------------------"
                    Write-Host "ID RawValues(6) Attribute Name"
                    continue
                }
                elseif ($line -match "-- IDENTIFY_DEVICE ------") {
                    # End of S.M.A.R.T. section
                    $inSmartSection = $false
                    Write-Host " "
                    Write-Host "----------------------------------------------------------------------------"
                    # Don't break here, as there might be more S.M.A.R.T. sections
                    continue
                }

                if ($inSmartSection) {
                    # Extract the relevant information (ID, RawValues, and Attribute Name)
                    $columns = $line -split '\s+'
                    $id = $columns[0]
                    $rawValue = $columns[1]
                    $attributeName = $columns[2,3,4,5,6,8,9,10]

                    # Convert the hexadecimal string to a decimal number using BigInteger
                    $decimalValue = [System.Numerics.BigInteger]::Parse($rawValue, [System.Globalization.NumberStyles]::HexNumber)


                    # Display the result
                    Write-Host "$id $decimalValue           $attributeName "
                } elseif (-not ($line -match "^($unneeded0|$unneeded1|$unneeded2|000:|010:|020:|0AE:|030:|040:|050:|060:|070:|080:|090:|100:|110:|120:|130:|140:|150:|160:|170:|180:|190:|200:|210:|220:|230:|240:|250:|1A0:|0A0:|0B0:|0D0:|1B0:|1C0:|0E0:|0C0:|0F0:|1E0:|1D0:|1F0:)")) { 
                    Start-Sleep -Milliseconds 10
                    Write-Host $line 
                }
            }
        }
                Write-Host "----------END---------- Press (Q)"
            Read-Host}
      #Network      
'NDT' { 
            Clear-Host

# Upgrade to admistrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated permissions
    Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
$currentDirectory = $PSScriptRoot
function Show-MainMenu {
    while ($true) {
        function Write-HostCenter {
            param($Message)
            Write-Host ("{0}{1}" -f (' ' * (([Math]::Max(0, $Host.UI.RawUI.BufferSize.Width / 2) - [Math]::Floor($Message.Length / 2)))), $Message) 
        }
        cls
        Write-HostCenter "=============== Network Diagnostic Tool Menu ===============" 
        $menuTable = @(
            [PSCustomObject]@{
                Selector = 'eip'
                Name = "External IP"
                Description = "Get External IP info from https://ipinfo.io/ or if blocked uses Amazon"
            }
            [PSCustomObject]@{
                Selector = 'info'
                Name = "Lan and Nic Info"
                Description = "IP Addressing, DNS, MACs, ROUTING, ECT"
            }
            [PSCustomObject]@{
                Selector = 'iperf3'
                Name = "iperf3.exe"
                Description = "iperf3 is for measuring TCP, UDP, and SCTP bandwidth performance on IP networks."
            }
            [PSCustomObject]@{
                Selector = "nmap"
                Name = "NMAP"
                Description = "Nmap is a network scanner for comprehensive discovery, service identification assessment of network devices."
            }
            [PSCustomObject]@{
                Selector = "tnc"
                Name = "Hello"
                Description = "Empty Space At the moment!"
            }
            [PSCustomObject]@{
                Selector = "q"
                Name = "Quit"
                Description = " "
            }
        )
        # Display the table
        $menuTable | Format-Table -AutoSize 
        $choice = Read-Host "Enter your choice" 
        switch ($choice) {
            'info' { Show-infoMenu }
            'eip' { Show-externalIPMenu }
            'iperf3' { iperf3-subMenu }
            'nmap' { nmap-subMenu }
            '3' { Show-SubMenu }
            'q' { Start-Process powershell -ArgumentList $currentDirectory\RTFM.ps1
            Exit }
            default { Write-Host "Invalid choice. Press ENTER and Please try again."  -ForegroundColor Red
            Read-Host }
        }
    }
}

function iperf3-submenu {
    while ($true) {
        $iperfPath = Get-ChildItem -Path $currentDirectory -Filter iperf3.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        if ($null -ne $iperfPath) {
        
        Clear-Host
        Write-Host "=== iperf3 ==="
        Write-Host "(C)lient Mode IPV4"
        Write-Host "(S)erver Mode IPV4"
        Write-Host "Custom (Args)"
        Write-Host "(Q) Back to Main Menu"
    } else {
        Write-Host "iperf3.exe not found in any subdirectory of the Tools directory." -ForegroundColor Red
        Get-Location 
        Read-Host
        Show-MainMenu
    }
        $subChoice = Read-Host "Enter your subchoice"

        switch ($subChoice) {
            'c' { 
                Clear-Host
                Write-host "This will run with -c applied"
                $iperfIP = Read-Host "Enter IPV4 Address"
                $iperfport = Read-Host "Enter A Port Number"
                $iperfArgs = Read-Host "Enter Aditional Argments if you want"
                Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "& '""$iperfPath""' -c $iperfIP -p $iperfport $iperfArgs"
                Read-Host
             }
            's' { 
                Clear-Host
                Write-host "This will run with -s applied"
                $iperfport = Read-Host "Enter A Port Number"
                $iperfArgs = Read-Host "Enter Aditional Argments if you want"
                Start-Process -FilePath $iperfPath -ArgumentList "-s -p $iperfport $iperfArgs"
                Read-Host
            }
        'args' {                 
            Clear-Host
            & "$iperfPath" | Out-Default
Write-Host $iperfHelp 
            $iperfArgs = Read-Host "Enter Args"
            Start-Process $iperfPath -ArgumentList "$iperfArgs"
            Read-Host 
        }
        'q' { Show-MainMenu }
        default { Write-Host "Invalid selection. Please choose again." 
                Read-Host}
        } 
    }
}

function nmap-subMenu {
    while ($true) {
        $nmapPath = Get-ChildItem -Path $currentDirectory -Filter nmap.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        $ncapKey = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  -EA SilentlyContinue | 
            Get-ItemProperty -EA SilentlyContinue |
            Where-Object {$_.DisplayName -like "*npcap*"} |
            Select-Object -First 1

        if ($null -ne $nmapPath -and $null -ne $ncapKey) {
            Get-Location | Write-Host
            Write-Host "=== NMAP MENU ==="
            Write-Host "NMAP (A)RGS"
            Write-Host "Custom NMAP Powershell Scipt(S)"
            Write-Host "(Q) Back to Main Menu"

            $subChoice = Read-Host "Enter your subchoice"
            
            switch ($subChoice) {
                'a' {
                    Clear-Host
                    Get-Location
                    & "$nmapPath" | Out-Default
                    $nmapArgs = Read-Host "Arguments for Nmap"
                    Get-Location
                    if ([string]::IsNullOrEmpty($nmapArgs)) {
                        nmap-subMenu
                    } else {
                    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "& '""$nmapPath""' $nmapArgs" -Verb RunAs


                }
            }
                's' { 
                    # Get the directory to search
$directory = ".\Tools\Networking\nmap*"

# Get all PowerShell scripts in the directory
$scripts = Get-ChildItem -Path $directory -Filter *.ps1 -Recurse

# Check if any scripts were found
if ($scripts.Count -eq 0) {
    Write-Host "No PowerShell scripts found in the directory."
    Read-Host
    return
    nmap-subMenu
}

# Display the scripts in a table
$scripts | Format-Table -Property Name

# Get the script to execute
$scriptName = Read-Host "Enter the name of the PS script to execute"

# Check if the script exists
$script = $scripts | Where-Object { $_.Name -eq $scriptName }
if ($null -eq $script) {
    Clear-Host
    Write-Host "The script '$scriptName' was not found in the directory."
    Read-Host
    return
    nmap-subMenu
}

# Execute the script
& $script.FullName
                }
                'q' { Show-MainMenu }
                default { Write-Host "Invalid subchoice. Please try again." }
            }
        } elseif ($null -eq $nmapPath -and $null -ne $ncapKey) {
            Write-Host "nmap is not in the tools directory." -ForegroundColor Red
            Read-Host
            Show-MainMenu
        } elseif ($null -ne $nmapPath -and $null -eq $ncapKey) {
            Write-Host "npcap.exe is not installed." -ForegroundColor Red
            Read-Host
            Show-MainMenu
        } else {
            Write-Host "npcap.exe not installed and NMAP is not in Tools Directory." -ForegroundColor Red
            Read-Host
            Show-MainMenu
        }
    }
}


function Show-externalIPMenu {
    while ($true) {
        Clear-Host
        Write-HostCenter "=============== External IP TOOL ===============" 
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

        $subChoice = Read-Host "Press (Q) to Quit"

        switch ($subChoice) {
            'q' {
                Show-MainMenu
            }
            default {
                Write-Host "Invalid selection. Please choose again."
                Read-Host
            }
        }
    }
}
function Show-InfoMenu {
    while ($true) {
        Clear-Host
        Write-HostCenter "=============== Network Info Menu ==============="
        Write-Host "Local" -ForegroundColor Magenta
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

# Windows Remote Desktop
$TermServ = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\CIMv2\TerminalServices
$RDPStatus = $TermServ.GetAllowTSConnections
if ($RDPStatus.ReturnValue -eq 0) {
    Write-Host "Windows Remote Desktop: Enabled."
} else {
    Write-Host "Windows Remote Desktop: Disabled."
}


#Check if any remote desktop apps are installed, in the registry
Write-Host "Checking for Remote Desktop programs found in registry..."

# Registry keys to search
$registryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

# List of remote desktop programs to check
$remoteAccessPrograms = @(
    "AeroAdmin",
    "Ammyy Admin",
    "AnyDesk",
    "Anyplace Control",
    "Apple Remote Desktop",
    "Bomgar",
    "Chrome Remote Desktop",
    "Cisco WebEx",
    "Citrix GoToAssist",
    "ConnectWise Control",
    "Dameware Remote Everywhere",
    "DeskRoll",
    "DWService",
    "FreeRDP",
    "GoToMyPC",
    "ISL Light",
    "ISL Online",
    "Join.me",
    "LiteManager",
    "LogMeIn",
    "Mikogo",
    "Microsoft Intune",
    "Microsoft Remote Desktop",
    "mRemoteNG",
    "NetSupport Manager",
    "NoMachine",
    "Parallels Access",
    "Radmin",
    "RDPSoft",
    "RDP Wrapper Library",
    "RealVNC",
    "Remote Desktop Commander",
    "Remote Desktop Connection Manager",
    "Remote Desktop Manager",
    "Remote Desktop Organizer",
    "Remote Desktop Plus",
    "Remote Desktop Spy",
    "RemoteToPC",
    "Remote Utilities",
    "Remmina",
    "ScreenConnect",
    "ShowMyPC",
    "SimpleHelp",
    "SolarWinds MSP Anywhere",
    "Splashtop",
    "Supremo",
    "SysAid",
    "TeamViewer",
    "Terminals",
    "Thinfinity Remote Desktop",
    "TightVNC",
    "UltraVNC",
    "VNC Connect",
    "WebEx",
    "Zoho Assist"
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

Write-Host "Checking for Remote Desktop Applications in Running Processes..."
$runningProcesses = Get-Process | Select-Object -ExpandProperty Name
foreach ($programName in $remoteAccessPrograms) {
    if ($runningProcesses -contains $programName) {
        Write-Host "$programName" -ForegroundColor Green -NoNewline
        Write-Host " is running."
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
Write-Host "Checking for VPN Programs in Registry"
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
# Check running processes
Write-Host "Checking for VPN Programs in Running Processes..."
$runningProcesses = Get-Process | Select-Object -ExpandProperty Name
foreach ($vpnName in $vpnNames) {
    if ($runningProcesses -contains $vpnName) {
        Write-Host "$vpnName" -ForegroundColor Green -NoNewline
        Write-Host " is running."
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


Write-Host "Wireless Info" -ForegroundColor Magenta 

netsh wlan show profiles
netsh wlan show wlanreport

Write-Host ""
Write-Host "----------END----------"
        $subChoice = Read-Host "Press (Q) to Quit"

        switch ($subChoice) {
            'q' {
                Show-MainMenu
            }
            default {
                Write-Host "Invalid selection. Please choose again."
                Read-Host
            }
        }
    }
}


Show-MainMenu
         }
        'App' { 


Clear-Host

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

        'ALL' { Write-Host "ALL" }
        'q' { exit }
        default { Write-Host "Invalid selection. Please choose again." }
    }
}
