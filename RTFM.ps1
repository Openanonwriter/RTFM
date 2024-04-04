#Writen By Anthony Widick
# Upgrade to admistrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated permissions
    Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
$Host.UI.RawUI.BackgroundColor = 'black'
$Host.UI.RawUI.ForegroundColor = 'white'
#Below are functions used to make life easier used in other functions. 
function Write-ColoredText {
    param (
        [string]$Text,
        [string]$Color = "White"  # Default color is white
    )

    # Validate color input
    $validColors = "Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray",
    "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White"
    if ($validColors -notcontains $Color) {
        Write-Host "Invalid color specified. Available colors: $($validColors -join ', ')" -ForegroundColor Red
        return
    }

    Write-Host $Text -ForegroundColor $Color
}
function Search-ItemPathByName {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ItemNames,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [string]$textcolor
    )
    
    # Search for the files and folders recursively and filter based on name
    $results = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue |
    Where-Object {
        foreach ($itemName in $ItemNames) {
            if ($_.Name -eq $itemName -or $_.Name -like "*$itemName*") {
                return $true
            }
        }
        return $false
    }

    # Output the names and full paths of the found items
    foreach ($result in $results) {
        Write-ColoredText "$($result.FullName)" $textcolor
    }
}
# Helper function for centering output
function Write-HostCenter($text) {
    $width = $host.UI.RawUI.BufferSize.Width
    $textWidth = $text.Length
    $spaces = [math]::Floor(($width - $textWidth) / 2)
    Write-Host (" " * $spaces) $text
}
#Below are Menues.
function OtherScripts {
    Clear-Host
    # Specify the directory to search for scripts
    $scriptDirectory = "$PSscriptroot/Tools/Scripts/"

    # Get all .ps1 files within the directory
    $scripts = Get-ChildItem -Path $scriptDirectory -Recurse -Filter "*.ps1"  | Select-Object -ExpandProperty BaseName

    # If no scripts are found, display a message
    if ($scripts.Count -eq 0) {
        Write-Host "No PowerShell scripts found in the 'script' directory."
        Read-Host
        return
    }

    # Display the scripts with a numbered list
    Write-Host "Available scripts:"
    for ($i = 0; $i -lt $scripts.Count; $i++) {
        Write-Host "$($i + 1). ) $($scripts[$i])"
    }

    Write-Host "Select a script number to execute (or 'q' to go back):"

    do {
        $selection = Read-Host 

        if ($selection -eq 'q') {
            break  # Go back to main menu
        }

        # Validate the selection (it's a number)
        if (-not [int]::TryParse($selection, [ref]$null)) {
            Write-Host "Invalid selection. Please enter a number from the list or 'q'."
            Read-Host
            OtherScripts  # Reprompt the user
        }

        # Convert to integer and adjust for zero-based indexing
        $selection = [int]$selection - 1 

        # Additional validation: selection is in range
        if (($selection -lt 0) -or ($selection -ge $scripts.Count)) {
            Write-Host "Invalid selection. Please enter a number from the list or 'q'."
            Read-Host
            OtherScripts  # Reprompt the user
        }

        # Retrieve the selected script name
        $selectedScriptName = $scripts[$selection]

        # Execute the selected script (add full path for execution)
        & "$scriptDirectory\$selectedScriptName.ps1" 
        Read-Host 

    } while ($true) # Loop until the user presses 'q'
}

function hardwareinfo{Clear-Host
    Write-Host "Motherboard" -ForegroundColor Magenta
    Get-WmiObject -Class Win32_BaseBoard | Format-Table Manufacturer, Product, SerialNumber, Version -Auto
    
    Write-Host "RAM" -ForegroundColor Magenta
    $ramInfo = Get-WmiObject -Class Win32_PhysicalMemory
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
            BankLabel        = $chip.BankLabel
            Manufacturer     = $chip.Manufacturer
            PartNumber       = $chip.PartNumber
            Speed            = $chip.Speed
            MemoryType       = $chip.MemoryType
            SMBIOSMemoryType = $chip.SMBIOSMemoryType
            DeviceLocator    = $chip.DeviceLocator
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
    
    # Get Video Card Info
    
    Write-Host "Basic Video Card info from Win32_VideoController, Better repacement on the way" -ForegroundColor Magenta
    $(Get-WmiObject Win32_VideoController | 
    Select-Object Name, DeviceID, VideoProcessor, DriverVersion, MinRefreshRate, MaxRefreshRate
    ) | Out-Default
    
    #Voltage PSU
    function PSUpowerCPUZ {
        Write-Host "Votage Parsed from CPU-Z" -ForegroundColor Magenta
        $currentDirectory = $PSScriptRoot
        $cpuzInfo = Get-ChildItem -Path $currentDirectory -Filter cpuz_x64.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
            & "$cpuzInfo" -txt=report
            do {
                $cpuzInfoPath = Get-ChildItem -Path $currentDirectory -Filter report.txt -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
                Start-Sleep -Seconds 1 # Pause before checking again
            } until ($cpuzInfoPath -ne $null)
            
            # The file exists and $cpuzInfoPath has a valid path
            $fileContent = Get-Content -Path $cpuzInfoPath -Raw
           
# Initialize variables to store the extracted voltage data
$voltage_12v_data = $null
$voltage_3_3v_data = $null
$voltage_5v_data = $null

# Regular expressions with a capture group for the data before "Volts"
$regex_12v = '\w		(.+)\s+Volts.*\(\+12V\)'
$regex_3_3v = '\w		(.+)\s+Volts.*\(\+3\.3V\)'
$regex_5v = '\w		(.+)\s+Volts.*\(\+5V\)'

while (-not (Test-Path $cpuzInfoPath)) {
   Start-Sleep -Seconds 1  
}

#write-host "$cpuzInfoPath"
$fileContent  = Get-Content -Path $cpuzInfoPath -Raw
# Check for +12V
if ($fileContent -match $regex_12v) { 
    $voltage_12v_data = $Matches[1] # Capture the data before "Volts"
} 

# Check for +3.3V
if ($fileContent -match $regex_3_3v) { 
    $voltage_3_3v_data = $Matches[1] 
}

# Check for +5V       
if ($fileContent -match $regex_5v) { 
    $voltage_5v_data = $Matches[1]  
}

$nominal_voltages = @{
    "+12V" = 12
    "+5V" = 5
    "+3.3V" = 3.3
}
# Define voltage thresholds (105% and 95% of nominal)
function  get_voltage_thresholds($nominal_voltage) {
    $high_threshold = $nominal_voltage * 1.05
    $low_threshold = $nominal_voltage * 0.95
    return $high_threshold, $low_threshold
}
# Function to check voltage and display warnings/beeps
function  check_voltage($voltage_name, $voltage_data) {
    $high_threshold, $low_threshold = get_voltage_thresholds($nominal_voltages[$voltage_name])
    if ($voltage_data -gt $high_threshold -or $voltage_data -lt $low_threshold) {
        Write-Host "WARNING: $voltage_name out of range!" -ForegroundColor red
        #[System.Console]::Beep(500, 1000)  # Beep for 1 second at 500 Hz
        Write-Host "**PSU Failure Likely!**" -ForegroundColor red
    }
}

$voltage_data = @{
    "+12V" = $voltage_12v_data
    "+5V" = $voltage_5v_data
    "+3.3V" = $voltage_3_3v_data
}


Write-Output "Extracted voltage values:"

# Check if any voltage data was found
$anyDataFound = $false
foreach ($voltage_name in $voltage_data.Keys) {
    $voltage_value = $voltage_data[$voltage_name] 

    if ($voltage_value -ne $null) {
        Write-Output "$voltage_name : $voltage_value"
        check_voltage $voltage_name $voltage_value
        $anyDataFound = $true 
    } else {
        Write-Output "$voltage_name : Unavailable"
    }
}

# If no data at all, print the "No ACPI DATA found" message
if (-not $anyDataFound) {
    Write-Host "No ACPI DATA found using CPU-Z" -ForegroundColor Yellow
}

if ($cpuzInfoPath -ne $null) { 
    $timeoutSeconds = 20 # Adjust as needed
    $startTime = Get-Date

    do { 
        try {
            Remove-Item "$cpuzInfoPath" -Force -ErrorAction Stop
        } catch {
            Write-Error "Error deleting file: $($_.Exception.Message)"
        }

        if (Test-Path $cpuzInfoPath) {
            Start-Sleep -Seconds 1
        } else {
            break  # Exit loop if the file is gone
        }

    } while ($true)
} 
Write-Output " "
#Check if CPU-Z exists, launch or write error message
    }
    
    $cpuzPath = Get-ChildItem -Path $PSScriptRoot -Filter "cpuz_x64.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName 
    # Check if the file exists, recursively searching subdirectories
if ($cpuzPath) {
    PSUpowerCPUZ
} else {
Write-Host "CPU-Z not found in Tools, skipping Voltage Check." -ForegroundColor Magenta
Write-Host " "
}

function SmartdataCrystalDisk{
    #Start of Crystal Disk
    Write-Host "PHYSICAL DISK INFO provided with CrystalDisk" -ForegroundColor Magenta
    Write-Host ""
    #do not need this variable, its already in rtfm later.
    $currentDirectory = $PSScriptRoot

    $cdiskinfo = Get-ChildItem -Path $currentDirectory -Filter DiskInfo64.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    & "$cdiskinfo" /CopyExit | Out-Null
    $diskinfoPath = Get-ChildItem -Path $currentDirectory -Filter DiskInfo.txt -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    $smartData = Get-Content -Path $diskinfoPath
    # Read the content of the text file (replace 'x.txt' with the actual file path)
    # Flag to indicate whether we are within the S.M.A.R.T. section
    $inSmartSection = $false
    $unneeded0 = '-- SMART_NVME --------------------------------------------------------------'
    $unneeded1 = "        0    1    2    3    4    5    6    7    8    9"
    $unneeded2 = '     \+0 \+1 \+2 \+3 \+4 \+5 \+6 \+7 \+8 \+9 \+A \+B \+C \+D \+E \+F'
    $unneeded3 = '-- SMART_READ_DATA ---------------------------------------------------------'
    $unneeded4 = '-- SMART_READ_THRESHOLD ----------------------------------------------------'
    
    $diskInfoContent = Get-Content -Path $diskinfoPath
    $healthStatuses = @()
    
    # Initialize variables to store the current disk's information
    $model = $null
    $status = $null
    $percentage = $null
    
    # Extract the model names, health status, and percentages from the content
    foreach ($line in $diskInfoContent) {
        if ($line -match "Model : (.*)") {
            # If a model is already set, add the previous disk's info to the array before resetting the variables
            if ($model) {
                $healthStatuses += @{
                    "Model"      = $model
                    "Status"     = $status
                    "Percentage" = $percentage
                }
            }
            $model = $matches[1]
            $status = $null
            $percentage = $null
        }
        elseif ($line -match "Health Status : (\w+) \((\d+) %\)") {
            $status = $matches[1]
            $percentage = [int]$matches[2]
        }
        elseif ($line -match "Health Status : (\w+)[^()]") {
            $status = $matches[1]
            $percentage = $null
        }
    }
    
    # Add the last disk's information if it hasn't been added yet
    if ($model) {
        $healthStatuses += @{
            "Model"      = $model
            "Status"     = $status
            "Percentage" = $percentage
        }
    }
    
    # Check the health status and percentage of each disk
    foreach ($disk in $healthStatuses) {
        $driveName = $disk.Model
        $healthStatus = $disk.Status
        $healthPercentage = $disk.Percentage
    
        #Write-Host "$driveName Health Status: $healthStatus" - ($healthPercentage ? " ($healthPercentage%)" : "")
        # Beep if the health percentage is below 80% or the status is not 'Good'
        if ((($healthPercentage -le 80) -and ($null -ne $healthPercentage)) -or ($healthStatus -notmatch '(G)')) {
            [console]::beep(1000, 1000)
            Write-Host "$driveName requires attention!" -ForegroundColor Red
        }
    }            
    # Process each line in the file
    if ($smartData -eq '-- SMART_READ_THRESHOLD ----------------------------------------------------') {
        foreach ($line in $smartData) {
            # Ignore empty lines and the line with 'ID RawValues(6) Attribute Name'
            if ([string]::IsNullOrWhiteSpace($line) -or $line -match "ID Cur Wor Thr RawValues\(6\) Attribute Name") {
                continue
            }

            if ($line -match "-- S.M.A.R.T. -------") {
                # Start of S.M.A.R.T. section
                $inSmartSection = $true
                Write-Host "-- S.M.A.R.T. --------------------------------------------------------------"
                Write-Host "ID Cur Wor Thr RawValues(6) Attribute Name"
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
                $currentValue = $columns[1]
                $worstValue = $columns[2]
                $threshValue = $columns[3]
                $attributeName = $columns[5, 6, 7, 8, 7, 8, 9]
                # Convert the hexadecimal string to a decimal number using BigInteger
                $decimalValue = [System.Numerics.BigInteger]::Parse($rawValue, [System.Globalization.NumberStyles]::HexNumber)


                # Display the result
                Write-Host "$id $currentValue $worstValue $threshValue" -NoNewline
                Write-Host " $decimalValue" -NoNewline -ForegroundColor Yellow
                Write-Host "   ----    $attributeName" -ForegroundColor Blue
            }
            elseif (-not ($line -match "^($unneeded4|$unneeded3|000:|010:|020:|0AE:|030:|040:|050:|060:|070:|080:|090:|100:|110:|120:|130:|140:|150:|160:|170:|180:|190:|200:|210:|220:|230:|240:|250:|1A0:|0A0:|0B0:|0D0:|1B0:|1C0:|0E0:|0C0:|0F0:|1E0:|1D0:|1F0:|$unneeded0|$unneeded1|$unneeded2)")) {
                # If not in a S.M.A.R.T. section and not a filtered line, print the line
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
                $attributeName = $columns[2, 3, 4, 5, 6, 8, 9, 10]

                # Convert the hexadecimal string to a decimal number using BigInteger
                $decimalValue = [System.Numerics.BigInteger]::Parse($rawValue, [System.Globalization.NumberStyles]::HexNumber)


                # Display the result
                Write-Host "$id $decimalValue           $attributeName "
            }
            elseif (-not ($line -match "^($unneeded0|$unneeded1|$unneeded2|000:|010:|020:|0AE:|030:|040:|050:|060:|070:|080:|090:|100:|110:|120:|130:|140:|150:|160:|170:|180:|190:|200:|210:|220:|230:|240:|250:|1A0:|0A0:|0B0:|0D0:|1B0:|1C0:|0E0:|0C0:|0F0:|1E0:|1D0:|1F0:)")) { 
                Start-Sleep -Milliseconds 10
                Write-Host $line
            }
        }
    }
    Remove-Item -Path $diskinfoPath
    Write-Host "----------END---------- Press (Q)"
    if ($cpuzInfoPath){
        do { Remove-Item $cpuzInfoPath -Force
            if (Test-Path $cpuzInfoPath) {
                Start-Sleep -Milliseconds 400
            }
        } until (-not (Test-Path $cpuzInfoPath))
    }
}
$crystaldiskPath = Get-ChildItem -Path $PSScriptRoot -Filter "DiskInfo64.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName 
    # Check if the file exists, recursively searching subdirectories
if ($crystaldiskPath) {
    SmartdataCrystalDisk
} else {
    Write-Host "CrystalDiskinfo not found in Tools, skipping indepth SmartData Check." -ForegroundColor Magenta
    Write-Host "Using Windows Win32_SMARTModel, built in to windows." -ForegroundColor Magenta
    $driveData = Get-WmiObject Win32_DiskDrive | Select-Object DeviceID, Model, Status  
    # Check if the query returned data
    if ($driveData) {
        # Process the drive data
        $driveData | ForEach-Object {
            Write-Host "Drive: $($_.DeviceID) - Model: $($_.Model) - Status: $($_.Status)"
        } 
    } else {
        Write-Error "WMI query failed to return drive data. Please investigate."
        # You might want to add a pause or exit the script here
    }

}
Read-Host
}


function windowsinfo{
    Clear-Host
    Write-ColoredText "Windows OS Information" Magenta

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
    $bootTime = $os.LastBootUpTime.Substring(0, 8)
    $bootYear = $bootTime.Substring(0, 4)
    $bootMonth = $bootTime.Substring(4, 2)
    $bootDay = $bootTime.Substring(6, 2)

    Write-Host "System Boot Time: $bootMonth/$bootDay/$bootYear"

    # Get the original install date
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $installDate = $os.InstallDate.Substring(0, 8)
    $installYear = $installDate.Substring(0, 4)
    $installMonth = $installDate.Substring(4, 2)
    $installDay = $installDate.Substring(6, 2)
    Write-Host "Original Install Date: $installMonth/$installDay/$installYear"

    # Get and display the Windows activation status
    $WinVerAct = (cscript /Nologo "C:\Windows\System32\slmgr.vbs" /dlv) -join ''
    $activationStatus = if ($WinVerAct -match 'Licensed') {
        'Licensed'
    }
    elseif ($WinVerAct -match 'Out-of-Box') {
        'Out-of-Box (OOB)'
    }
    elseif ($WinVerAct -match 'Non-Genuine Grace') {
        'Non-Genuine Grace'
    }
    elseif ($WinVerAct -match 'Out of Tolerance Grace') {
        'Out of Tolerance (OOT) Grace'
    }
    elseif ($WinVerAct -match 'Unlicensed') {
        'Unlicensed'
    }
    elseif ($WinVerAct -match 'Notification') {
        'Notification'
    }
    elseif ($WinVerAct -match 'Extended Grace') {
        'Extended Grace'
    }
    else {
        'Unknown'
    }

    # Initialize the license type
    $licenseType = "Unknown"

    # Check for different product key channels
    if ($WinVerAct -match 'Product Key Channel: STA') {
        $licenseType = 'Static Activation Key (STA)'
    }
    elseif ($WinVerAct -match 'Product Key Channel: OEM') {
        $licenseType = 'OEM (Original Equipment Manufacturer)'
    }
    elseif ($WinVerAct -match 'Product Key Channel: Retail') {
        $licenseType = 'Retail (FPP, Boxed Copy)'
    }
    elseif ($WinVerAct -match 'Product Key Channel: VL1') {
        $licenseType = 'Volume License (VL1)'
    }
    elseif ($WinVerAct -match 'Product Key Channel: FPP') {
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
            }
            else {
                Write-Warning "Value '$keyName' was not found."
            }
        }
        catch {
            # Handle potential errors during retrieval 
            Write-Host "Unable to Retrive key from Registry"
            #Write-Host "Error retrieving the value: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Registry path '$registryPath' does not exist."
    }


    #There is an error here, still have not found it, saw it on a computer once and trying to remember. It might be here at Get-Bitlockervolume with 
    # windows default error handling yelling in the terminal. Dont want to add 2> $null until i know what it is, or if i can better handle. 
    $BitLockerStatus = (Get-BitLockerVolume -MountPoint C:).ProtectionStatus
    # $BitLockerStatus = 'OFF'
    if ($BitLockerStatus -eq "On") {
        #$bitlockeroutput = "207284-425711-631675-392370-433455-420673-432069-07249"
        $bitlockeroutput = manage-bde -protectors -get C:
        $pattern = "\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}"
        $bitlockercode = $bitlockeroutput -match $pattern

        # Write-Host $Matches}
        if ($bitlockeroutput -match $pattern) {
            Write-host "BitLocker: " -NoNewline
            Write-host "Enabled" -ForegroundColor Red
            Write-host "Recovery Key:" -NoNewline
            write-host $bitlockercode -BackgroundColor Black -ForegroundColor Red
        }
        else {
            Write-host "Recovery Key not found in the output" # More informative message
        }
    }
    else {
        Write-host "BitLocker: " -NoNewline
        Write-host "Disabled" -ForegroundColor Green 
    }   
    
    Write-host " "
    Write-ColoredText "Windows Partiton Type" Magenta

    $disks = Get-Disk

    foreach ($disk in $disks) {
        $partitionStyle = $disk.PartitionStyle
        $diskNumber = $disk.Number

        # Get volumes associated with the current disk
        $volumes = Get-Partition -DiskNumber $disk.Number 2> $null | Get-Volume 

        $windowsDriveLetter = ($env:SystemDrive -replace ':').Trim()  
        # Check if there's a C: volume on this disk
        $hasVolumeC = $volumes | Where-Object { $_.DriveLetter -eq $windowsDriveLetter } 

        if ($hasVolumeC) { 
            if ($partitionStyle -eq "MBR") {
                Write-Host "Windows is (MBR) Disk:$diskNumber"
            }
            elseif ($partitionStyle -eq "GPT") {
                Write-Host "Windows is (GPT) Disk:$diskNumber"
            }
            else {
                Write-Host "Disk $diskNumber (unknown partition style) is associated with volume C:"
            }
        }
    }

    Write-ColoredText "Checking Disk Cappacity" Magenta
    # Set the threshold for disk usage
    $usageThreshold = 90

    # Get all logical disks
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk

    # Check each disk's usage
    foreach ($disk in $disks) {
        if ($disk.Size -ne $null) {
            $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
            $usedSpacePercent = 100 - $freeSpacePercent

            # If the used space exceeds the threshold, beep
            if ($usedSpacePercent -ge $usageThreshold) {
                [console]::Beep(1000, 1000) # Beep for 1 second at 1000 Hz
                Write-Host "Disk $($disk.DeviceID) is at " -NoNewline
                Write-Host "$usedSpacePercent%" -ForegroundColor Red -NoNewline
                Write-Host " capacity."
            }
            else {
                Write-Host "Disk $($disk.DeviceID) is at $usedSpacePercent% capacity."
            }
        }
    }

    #Anti-Virus
    write-host "Active Anti-Virus"-ForegroundColor Magenta
    function Get-AntiVirusProduct {
        [CmdletBinding()]
        param (
            [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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
                ComputerName       = $computername
                ProductName        = $AntiVirusProduct.displayName
                DefinitionStatus   = $status
                RealTimeProtection = $realTimeProtection
            }
        }

        $ret
    }
    Get-AntiVirusProduct | Out-String

    # Windows Updates
    Write-Host "Windows Updates" -ForegroundColor Magenta

    # Check for internet connectivity
    $pingResult = Test-Connection -ComputerName microsoft.com -Count 1 -Quiet

    if ($pingResult) {
        # Create a session to interact with Windows Update
        try {
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
        }
        catch {
            Write-Host "An error occurred while checking for updates: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "No network connection. Please check your internet connectivity."
    }

    Write-Host ' '
    # Diagnostic data
    Write-Host "Diagnostic Data" -ForegroundColor Magenta
    
    # SFC
    $cbslog = Get-Content -Path "$env:windir\Logs\CBS\CBS.log"
    # Find the last line that contains the string "[SR]"
    if ($lastSfcLine = $cbslog | Select-String -Pattern "Repair complete" | Select-Object -Last 1) {
        $lastSfcDate = $lastSfcLine.Line.Substring(0, 19)
        Write-Host "The last time SFC was ran was $lastSfcDate."
    } 
    else { 
        $rotationDateString = $cbslog | Select-Object -First 1
        $rotationDate = $rotationDateString.Substring(0, 19)
        Write-Host "SFC last run is not in CBS log since: $rotationDate" 
    }
    
    Write-Host " "

    $miniDumpPath = "C:\Windows\Minidump"
    $miniDumps = Get-ChildItem -Path $miniDumpPath -Filter "*.dmp" -File -ErrorAction SilentlyContinue
    
    # Mini Dumps
    if ($miniDumps.Count -gt 0) {
        Write-Host "Mini-Dumps found: " -NoNewline 
        Write-Host "$($miniDumps.Count)" -ForegroundColor Red
    }
    else {
        Write-Host "Mini-Dumps found: 0"
    }
    Write-Host ""
    Write-host "Bugcheck 1001 Codes from Event Log"
        $FilterHashtable = @{
        LogName = 'System'
        ID = 1001
    }
    
    # Get the events
    $events = Get-WinEvent -FilterHashtable $FilterHashtable 2> $null
    
    # Initialize a counter for numbering
    $counter = 1
    
    # Loop through each event and format the output
    foreach ($event in $events) {
        # Extract the BugCheckCode values
        $bugCheckCode = ($event.Properties[0].Value -split ' ')[0]
        $bugCheckParam1 = ($event.Properties[0].Value -split '[,|(]')[1]
        $bugCheckParam2 = ($event.Properties[0].Value -split '[,|(]')[2]
        $bugCheckParam3 = ($event.Properties[0].Value -split '[,|(]')[3]
        $bugCheckParam4 = ($event.Properties[0].Value -split '[,|(|)]')[4]
    
$formattedOutput = @"
$counter. ---------------------------
Bugcheck Date: $($event.TimeCreated.ToString('MM/dd/yyyy HH:mm:ss'))
BugCheckCode: $bugCheckCode
BugCheckParameter1: $bugCheckParam1
BugCheckParameter2: $bugCheckParam2
BugCheckParameter3: $bugCheckParam3
BugCheckParameter4: $bugCheckParam4

"@
        Write-Host $formattedOutput
        $counter++
    }
    Write-Host "--------Press [Enter] to return to Main Menu--------"
    Read-Host
}

function networkdiagnostictool {while ($true) {
    function Write-HostCenter {
        param($Message)
        Write-Host ("{0}{1}" -f (' ' * (([Math]::Max(0, $Host.UI.RawUI.BufferSize.Width / 2) - [Math]::Floor($Message.Length / 2)))), $Message) 
    }
    Clear-Host
    Write-HostCenter "=============== Network Diagnostic Tool Menu ===============" 
    $menuTable = @(
        [PSCustomObject]@{
            Selector    = 'eip'
            Name        = "External IP"
            Description = "Get External IP info from https://ipinfo.io/ or if blocked uses Amazon"
        }
        [PSCustomObject]@{
            Selector    = 'info'
            Name        = "Lan and Nic Info"
            Description = "IP Addressing, DNS, MACs, ROUTING, ECT"
        }
        [PSCustomObject]@{
            Selector    = "tnc"
            Name        = "Hello"
            Description = "Empty Space At the moment!"
        }
        [PSCustomObject]@{
            Selector    = "q"
            Name        = "Quit"
            Description = " "
        }
    )
    # Display the table
    $menuTable | Format-Table -AutoSize 
    $choice = Read-Host "Enter your choice" 
    switch ($choice) {
        'info' { Show-infoMenu }
        'eip' { while ($true) {
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
        Read-Host
        } 
    }
        'q' { Show-Menu }
        default {
            Write-Host "Invalid choice. Press ENTER and Please try again."  -ForegroundColor Red
            Read-Host 
        }
    }
    break
}
break
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
        Write-Host "NetBIOS over Tcpip: $($null -ne $adapter.WINSPrimaryServer)"
        Write-Host "IPv6 Enabled: $($adapter.IPv6Enabled)"
        Write-Host
    }

    Write-Host "Wireless Info" -ForegroundColor Magenta 

    netsh wlan show profiles
    netsh wlan show wlanreport

    Write-Host "Remote Accesss" -ForegroundColor Magenta
    # WinRM
    $winrmStatus = Get-WmiObject -Class Win32_Service -Filter "Name = 'winrm'"
    if ($winrmStatus.State -eq "Running") {
        Write-Host "WinRM: Enabled"
    }
    else {
        Write-Host "WinRM: Disabled"
    }
    #check for SSH Server
    $sshServerInstalled = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($sshServerInstalled.State -eq 'Installed') {
        # Check if OpenSSH SSH Server service is running
        $sshServiceStatus = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($sshServiceStatus.Status -eq 'Running') {
            Write-Host "OpenSSH SSH Server: " -NoNewline
            Write-Host "RUNNING" -ForegroundColor Red
        }
        else {
            Write-Host "OpenSSH SSH Server: " -NoNewline
            Write-Host "INSTALLED, NOT RUNNING." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "OpenSSH Server: NOT INSTALLED."
    }
    
    # Windows Remote Desktop
    $TermServ = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\CIMv2\TerminalServices
    $RDPStatus = $TermServ.GetAllowTSConnections
    if ($RDPStatus.ReturnValue -eq 0) {
        Write-Host "Windows Remote Desktop: Enabled."
    }
    else {
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
    Write-Host "Checking in %APPDATA% for VPN files: " -ForegroundColor Blue
    $appdata = [Environment]::GetFolderPath("ApplicationData")
    Search-ItempathByName -path $appData -itemName $remoteAccessPrograms -textcolor Red 

    
    
    #search Registry keys
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

    Write-Host "Checking for Remote Desktop Applications in Running Processes..." -ForegroundColor Blue
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
    Write-Host "Checking in %APPDATA% for VPN with matching names to VPN List: " -ForegroundColor Blue
    $appdata = [Environment]::GetFolderPath("ApplicationData")
    Search-ItempathByName -path $appData -itemName $vpnNames -textcolor Red 
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
    Write-Host "Checking for VPN Programs in Running Processes..." -ForegroundColor Blue
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
    $subChoice = Read-Host "Press (Q) to Quit"

    switch ($subChoice) {
        'q' { return }
        default {
            Write-Host "Invalid selection. Please choose again."
            Read-Host
}}}}

function about{
    $Host.UI.RawUI.BackgroundColor = 'black'
    $Host.UI.RawUI.ForegroundColor = 'DarkGreen'
    Clear-Host
    Function TypeDynamic([Int32]$DelayMin, [Int32]$DelayMax, [String]$String) {
        For ($i = 0; $i -lt $String.Length; $i++) {
            Write-Host $String[$i] -NoNewLine -ForegroundColor Green
            $Delay = Get-Random -Minimum $DelayMin -Maximum $DelayMax
            Start-Sleep -Milliseconds $Delay
        }
        Write-Host
    }
    
    Write-Host "Loading..." -ForegroundColor Yellow
    TypeDynamic 1 2   'RRRRRRRRRRRRRRRRR   TTTTTTTTTTTTTTTTTTTTTTTFFFFFFFFFFFFFFFFFFFFFFMMMMMMMM               MMMMMMMM'
    TypeDynamic 1 2   'R::::::::::::::::R  T:::::::::::::::::::::TF::::::::::::::::::::FM:::::::M             M:::::::M'
    TypeDynamic 1 2   'R::::::RRRRRR:::::R T:::::::::::::::::::::TF::::::::::::::::::::FM::::::::M           M::::::::M'
    TypeDynamic 1 2   'RR:::::R     R:::::RT:::::TT:::::::TT:::::TFF::::::FFFFFFFFF::::FM:::::::::M         M:::::::::M'
    TypeDynamic 1 2   '  R::::R     R:::::RTTTTTT  T:::::T  TTTTTT  F:::::F       FFFFFFM::::::::::M       M::::::::::M'
    TypeDynamic 1 2   '  R::::R     R:::::R        T:::::T          F:::::F             M:::::::::::M     M:::::::::::M'
    TypeDynamic 1 2   '  R::::RRRRRR:::::R         T:::::T          F::::::FFFFFFFFFF   M:::::::M::::M   M::::M:::::::M'
    TypeDynamic 1 2   '  R:::::::::::::RR          T:::::T          F:::::::::::::::F   M::::::M M::::M M::::M M::::::M'
    TypeDynamic 1 2   '  R::::RRRRRR:::::R         T:::::T          F:::::::::::::::F   M::::::M  M::::M::::M  M::::::M'
    TypeDynamic 1 2   '  R::::R     R:::::R        T:::::T          F::::::FFFFFFFFFF   M::::::M   M:::::::M   M::::::M'
    TypeDynamic 1 2   '  R::::R     R:::::R        T:::::T          F:::::F             M::::::M    M:::::M    M::::::M'
    TypeDynamic 1 2   '  R::::R     R:::::R        T:::::T          F:::::F             M::::::M     MMMMM     M::::::M'
    TypeDynamic 1 2   'RR:::::R     R:::::R      TT:::::::TT      FF:::::::FF           M::::::M               M::::::M'
    TypeDynamic 1 2   'R::::::R     R:::::R      T:::::::::T      F::::::::FF           M::::::M               M::::::M'
    TypeDynamic 1 2   'R::::::R     R:::::R      T:::::::::T      F::::::::FF           M::::::M               M::::::M'
    TypeDynamic 1 2   'RRRRRRRR     RRRRRRR      TTTTTTTTTTT      FFFFFFFFFFF           MMMMMMMM               #WIDICK#'
                                                                                                    
    
    TypeDynamic 1 5 "Made you wait"
Write-Host "
RTFM is a modular PowerShell script designed for rapid computer diagnostics and information gathering. 
It encapsulates and relies upon a curated selection of third-party tools within a menu-driven interface. 
I'm using AI capabilities to accelerate RTFM's development with rapid error checking and I invite collaboration.
"  -ForegroundColor Yellow
    
    # https://www.patorjk.com/ For the RTFM Logo
    # https://github.com/urbanware-org/typefx - For the code to make code type like a typewriter
    # MIT License
    #Copyright © 2018, 2019 by Ralf Kilian
    #Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    #The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    #THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    $subChoice = Read-Host "Press (Q) to Quit"

    switch ($subChoice) {
        'q' { return }
        default {
            Write-Host "Invalid selection. Please choose again."
            Read-Host}}
}

# Everything Below Here is about has to do with the menu

function MainMenu {
    param (
    )
    Clear-Host
    $Host.UI.RawUI.BackgroundColor = 'black'
    $Host.UI.RawUI.ForegroundColor = 'white'
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
    $bootTime = $os.LastBootUpTime.Substring(0, 8)
    $bootYear = $bootTime.Substring(0, 4)
    $bootMonth = $bootTime.Substring(4, 2)
    $bootDay = $bootTime.Substring(6, 2)

    Write-Host "System Boot Time: $bootMonth/$bootDay/$bootYear"

    # Get the original install date
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $installDate = $os.InstallDate.Substring(0, 8)
    $installYear = $installDate.Substring(0, 4)
    $installMonth = $installDate.Substring(4, 2)
    $installDay = $installDate.Substring(6, 2)
    Write-Host "Original Install Date: $installMonth/$installDay/$installYear"

    #There is an error here, still have not found it, saw it on a computer once and trying to remember. It might be here at Get-Bitlockervolume with 
    # windows default error handling yelling in the terminal. Dont want to add 2> $null until i know what it is, or if i can better handle. 
    $BitLockerStatus = (Get-BitLockerVolume -MountPoint C:).ProtectionStatus
    # $BitLockerStatus = 'OFF'
    if ($BitLockerStatus -eq "On") {
        #$bitlockeroutput = "207284-425711-631675-392370-433455-420673-432069-07249"
        $bitlockeroutput = manage-bde -protectors -get C:
        $pattern = "\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}"
        $bitlockercode = $bitlockeroutput -match $pattern

        # Write-Host $Matches}
        if ($bitlockeroutput -match $pattern) {
            Write-host "BitLocker: " -NoNewline
            Write-host "Enabled" -ForegroundColor Red
            Write-host "Recovery Key:" -NoNewline
            write-host $bitlockercode -BackgroundColor Black -ForegroundColor Red
        }
        else {
            Write-host "Recovery Key not found in the output" # More informative message
        }
    }
    else {
        Write-host "BitLocker: " -NoNewline
        Write-host "Disabled" -ForegroundColor Green 
    }   

    # Your menu table definition
    $menuTable = @(
        [PSCustomObject]@{ Selector = 'h';   Name = "Hardware Infomation"; 
                           Description = "Basic Hardware info, full Smart Data, and PSU Voltage if aplictable" }
        [PSCustomObject]@{ Selector = 'w';  Name = "Windows Infomation"; 
                           Description = "Windows Key, Bitlocker Key, Uptime, BSOD Error Codes, Disk% Full" }
        [PSCustomObject]@{ Selector = 'n'; Name = "Network Diagnostic Tool"; 
                           Description = "View Basic Network infomation, external IP" }
        [PSCustomObject]@{ Selector = 'o';   Name = "Additional Scripts"; 
                           Description = "Run Additional Powershell Scripts placed under in /Tools/Scripts" }
        [PSCustomObject]@{ Selector = 'g';   Name = "All Settings"; 
                           Description = "This is an event variable known as God Mode" }
        [PSCustomObject]@{ Selector = 'a';   Name = "About"; 
                           Description = "Shows information about this program" }
        [PSCustomObject]@{ Selector = 'u';   Name = "Reboot to UEFI/BIOS"; 
                           Description = "Directly Reboot to UEFI/BIOS with out having to hit F12 or ESC" }
        [PSCustomObject]@{ Selector = 'q';     Name = "Quit"; Description = " " }
    )

    # Display the table
    $menuTable | Format-Table -AutoSize 

    
    Write-Host "Enter your selection:" # Prompt for user input
    
}

function Get-KeyPress {
    $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    return $key.Character 
}

# Main execution loop
while ($true) {
    Clear-Host
    # Display the menu
    MainMenu -Title 'My Menu'

    # Get user input
    $selection = Get-KeyPress

    # Process the input using a switch statement
    switch ($selection) {
        'h' {
            hardwareinfo
        }
        'w' {
            windowsinfo
        }
        'n' {
            networkdiagnostictool
        }
        'a' {
            about   
        }
        'o' {
            OtherScripts
        }
        'g'{
            Start-Process "shell:::{ED7BA470-8E54-465E-825C-99712043E01C}" #GodMode
        }
        'u'{
            shutdown /r /fw /t 10 /c "Reboot to UEFI/BIOS initiated via RTFM"
        }
        'q' {
            exit
              # Exit the loop
        }
        default {
            Write-Host "Invalid selection. Please choose a valid option. "-NoNewline 
            Read-Host  # Pause before returning to the menu
        }
    } # End switch
}  # End while