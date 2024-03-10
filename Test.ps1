Clear-Host

# Find iperf3.exe in any subdirectory of the current directory
$iperfPath = Get-ChildItem -Path .\ -Filter iperf3.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

if ($null -ne $iperfPath) {
    Write-Host "iperf3 found at $iperfPath"
    Write-Host "This will run with -s applied"

    $iperfport = Read-Host "Enter A Port Number"
    $iperfArgs = Read-Host "Enter Additional Arguments if you want"

    Write-Host "Starting iperf3 from $iperfPath"
    Start-Process -FilePath $iperfPath -ArgumentList "-s -p $iperfport $iperfArgs"
} else {
    Write-Host "iperf3.exe not found in any subdirectory of the Tools directory."
}

Read-Host