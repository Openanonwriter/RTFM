function Find-PiperFiles {
    param (
        [string]$searchPath = $env:APPDATA,
        [string]$fileName = 'chrome.exe'
    )
    Get-ChildItem -Path $searchPath -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { !$_.PSIsContainer -and $_.Name -eq $fileName }
}


# Call the function
Find-PiperFiles