$diskinfoPath = Get-ChildItem -Path $currentDirectory -Filter DiskInfo.txt -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
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
                "Model" = $model
                "Status" = $status
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
        "Model" = $model
        "Status" = $status
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
    if ((($healthPercentage -le 80) -and ($healthPercentage -ne $null)) -or ($healthStatus -notmatch '(G)')) {
        [console]::beep(1000,1000)
        Write-Host "$driveName requires attention!" -ForegroundColor Red
    }
}
