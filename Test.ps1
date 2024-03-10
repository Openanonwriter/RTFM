# Get the directory to search
$directory = ".\Tools\Networking\nmap*"

# Get all PowerShell scripts in the directory
$scripts = Get-ChildItem -Path $directory -Filter *.ps1 -Recurse

# Check if any scripts were found
if ($scripts.Count -eq 0) {
    Write-Host "No PowerShell scripts found in the directory."
    Read-Host
    return
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
}

# Execute the script
& $script.FullName