function Show-MainMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Network Diagnostic Tool Menu ==="
        Write-Host "(iperf3) Bandwith Test"
        Write-Host "(nmap) Check ports and hosts on network"
        Write-Host "(TNC)Test-NetConnection"
        Write-Host "(Ping)"
        Write-Host "(Trace)Trace Route"

        $choice = Read-Host "Enter your choice"

        switch ($choice) {
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
        
        $iperfPath = Get-ChildItem -Path .\ -Filter iperf3.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        if ($null -ne $iperfPath) {
        
        Clear-Host
        Write-Host "=== iperf3 ==="
        Write-Host "(C)lient Mode IPV4"
        Write-Host "(S)erver Mode IPV4"
        Write-Host "Custom (Args)"
        Write-Host "(Q) Back to Main Menu"
    } else {
        Write-Host "iperf3.exe not found in any subdirectory of the Tools directory." -ForegroundColor Red
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
                Start-Process -FilePath $iperfPath -ArgumentList "-c $iperfIP -p $iperfport $iperfArgs"
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
        $nmapPath = Get-ChildItem -Path .\ -Filter nmap.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
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


Show-MainMenu