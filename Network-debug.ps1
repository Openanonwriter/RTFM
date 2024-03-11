
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
                Description = "World!"
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
            'q' { exit }
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