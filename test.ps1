if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated permissions
    Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    
}
$Adapters = Get-NetAdapter

# Filter for wireless adapters
$WirelessAdapter = $Adapters | Where-Object {$_.PhysicalMediaType -eq "Native 802.11"}
Write-Host "Wireless Info"
# Check if a wireless adapter was found 
if ($WirelessAdapter) {
    Write-Output "Wireless card installed"
    netsh wlan show profiles
    netsh wlan show wlanreport
} else {
    Write-Output "No Wireless card installed"
}
Pause