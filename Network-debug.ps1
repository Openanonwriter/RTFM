function Show-MainMenu {
    while ($true) {
        Write-Host "=== Network Diagnostic Tool Menu ==="
        Write-Host "(iperf3) Bandwith Test"
        Write-Host "(nmap) Check ports and hosts on network"
        Write-Host "(TNC)Test-NetConnection"
        Write-Host "(Ping)"
        Write-Host "(Tracert) Trace Route"

        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            'iperf3' { Write-Host "You chose Option 1" }
            '2' { Write-Host "You chose Option 2" }
            '3' { Show-SubMenu }
            'q' { break }
            default { Write-Host "Invalid choice. Please try again." }
        }
    }
}


function Show-SubMenu {
    while ($true) {
        Write-Host "=== Submenu ==="
        Write-Host "A. Suboption A"
        Write-Host "B. Suboption B"
        Write-Host "Q. Back to Main Menu"

        $subChoice = Read-Host "Enter your subchoice"

        switch ($subChoice) {
            'a' { Write-Host "You chose Suboption A" }
            'b' { Write-Host "You chose Suboption B" }
            'q' { break }
            default { Write-Host "Invalid subchoice. Please try again." }
        }
    }
}

Show-MainMenu