function iperf3submenu {
    while ($true) {
        # Get the parent directory of the current script's location
        $parentDirectory = Split-Path -Parent $PSScriptRoot 
        $iperfPath = Get-ChildItem -Path $parentDirectory -Filter iperf3.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        if ($null -ne $iperfPath) {
    
            Clear-Host
            Write-Host "=== iperf3 ==="
            Write-Host "(C)lient Mode IPV4"
            Write-Host "(S)erver Mode IPV4"
            Write-Host "Custom (Args)"
            Write-Host "(Q) Back to Main Menu"
        }
        else {
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
            'q' { return }
            default {
                Write-Host "Invalid selection. Please choose again." 
                Read-Host
            }
        } 
    }
    }
    iperf3submenu