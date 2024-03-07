function Show-Menu {
    param (
        [string]$Title = 'My Menu'
    )
	clear-host
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

Write-Host ""
    Write-Host "================ $Title ================"
    Write-Host "1: Hardware"
    Write-Host "2: Networking"
    Write-Host "3: Remote Access"
    Write-Host "4: Security"
    Write-Host "5: Option 5"
    Write-Host "6: Option 6"
    Write-Host "ALL"
    Write-Host "Q: Quit"
}

while ($true) {
    Show-Menu -Title 'RTFM Main Menu'
    $selection = Read-Host "Please make a selection"

    switch ($selection) {
        '1' { 
			clear-host
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
			
			Write-Host ""
			Write-Host "CPU" -ForegroundColor Magenta
			$cpuInfo = Get-WmiObject -Class Win32_Processor
			Write-Host "Name: $($cpuInfo.Name)"
			Write-Host "Socket: $($cpuInfo.SocketDesignation)"
			Write-Host "# of Sockets: $((Get-WmiObject -Class Win32_ComputerSystem).NumberOfProcessors)"
			Write-Host "# of Cores: $($cpuInfo.NumberOfCores)"
			Write-Host "# of Threads: $($cpuInfo.NumberOfLogicalProcessors)"
			Write-Host "Max Clock Speed: $($cpuInfo.MaxClockSpeed) Mhz"
		Read-Host}
        '2' { Write-Host "Networking" }
        '3' { Write-Host "Remote Access" }
        '4' { Write-Host "AV" }
        '5' { Write-Host "You chose Option 5" }
        '6' { Write-Host "You chose Option 6" }
        'ALL' { Write-Host "ALL" }
        'q' { exit }
        default { Write-Host "Invalid selection. Please choose again." }
    }
}
