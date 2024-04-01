function nmapsubMenu {
    while ($true) {
        $parentDirectory = Split-Path -Parent $PSScriptRoot 
        $nmapPath = Get-ChildItem -Path $parentDirectory -Filter nmap.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        $ncapKey = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  -EA SilentlyContinue | 
        Get-ItemProperty -EA SilentlyContinue |
        Where-Object { $_.DisplayName -like "*npcap*" } |
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
                        nmapsubMenu
                    }
                    else {
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
                        nmapsubMenu
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
                        nmapsubMenu
                    }
    
                    # Execute the script
                    & $script.FullName
                }
                'q' {
                    Return 
                    break
                }
                default { Write-Host "Invalid subchoice. Please try again." }
            }
        }
        elseif ($null -eq $nmapPath -and $null -ne $ncapKey) {
            Write-Host "nmap is not in the tools directory." -ForegroundColor Red
            Read-Host
            break
        }
        elseif ($null -ne $nmapPath -and $null -eq $ncapKey) {
            Write-Host "npcap.exe is not installed." -ForegroundColor Red
            Read-Host
            break
        }
        else {
            Write-Host "npcap.exe not installed and NMAP is not in Tools Directory." -ForegroundColor Red
            Read-Host
            break
        }
        break    
    } 
    }
    nmapsubMenu