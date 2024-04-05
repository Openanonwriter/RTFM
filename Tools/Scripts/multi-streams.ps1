## Currently has many issues. Do not run atm, still testing. 
## This script looks for hidden streams of data. 
## Anthony Widick 

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated permissions
    Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}


$directory = "C:\"
$files = Get-ChildItem -File -Recurse -Path $directory 2>$null
# Iterate through each file
foreach ($file in $files) {
    if (Test-Path -LiteralPath $file.FullName -PathType Leaf) {
        $streams = (Get-Item -Path $file.FullName -Stream * 2>$null)


    # Filter out the Zone.Identifier and $DATA streams
    $filteredStreams = $streams | Where-Object { $_.Stream -notin @("Zone.Identifier", ":$DATA") } 

    # If there are multiple streams (excluding Zone.Identifier and $DATA), display the file name
    if ($filteredStreams.Count -gt 1) {
        Write-Host "File with multiple streams: $($file.FullName)" 
        foreach ($stream in $filteredStreams) {
            Write-Host "  Stream: $($stream.Stream)"
        }
        Write-Host
    }
}
}
Write-Output "Done!"
Read-Host