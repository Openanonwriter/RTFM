# Upgrade to admistrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated permissions
    Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define the target value
$targetValue = "458722-253748-230274-265155-543048-520751-279191-513590"

# Search all registry hives (HKLM and HKCU)
$registryHives = "Registry::HKEY_LOCAL_MACHINE", "Registry::HKEY_CURRENT_USER"

foreach ($hive in $registryHives) {
    # Get all subkeys recursively
    $subkeys = Get-ChildItem -Path $hive -Recurse -ErrorAction SilentlyContinue

    foreach ($subkey in $subkeys) {
        # Get property names and values for each subkey
        $properties = Get-ItemProperty -Path $subkey.PSPath -ErrorAction SilentlyContinue

        foreach ($property in $properties.PSObject.Properties) {
            # Check if the value contains the target value
            if ($property.Value -like "*$targetValue*") {
                Write-Host "Found in key: $($subkey.PSPath)"
                break
            }
        }
    }
}
