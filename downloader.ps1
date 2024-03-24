#Writen By Anthony Widick
# Upgrade to admistrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated permissions
    Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
# -- 1. Define Download URL, File Paths, and Directories --

# $downloadUrl = "https://download.cpuid.com/cpu-z/cpu-z_2.09-en.zip"  
# $outputFolder = "$PSScriptRoot\Tools\Hardware\CPU-Z\"  # Includes subfolders
# $zipfileName = "cpu-z.zip"
# $zipFile = Join-Path $outputFolder $zipfileName
# Write-Host $zipFile
# Write-Host $outputFolder -ForegroundColor DarkMagenta
# Write-Host $zipFile -ForegroundColor DarkMagenta

# # -- 2. Create Directories if They Don't Exist --

# if (!(Test-Path $outputFolder)) {
#     New-Item -ItemType Directory -Path $outputFolder -Force
# }
# Write-Host $downloadUrl
# # -- 3. Download the Zip File -- 

# Invoke-WebRequest $downloadUrl -OutFile $zipFile

# # -- 4. Unzip the Downloaded File --

# Expand-Archive -Path $zipFile -DestinationPath $outputFolder -Force

# # -- 5. Delete .Zip

#  Remove-Item $zipFile
# Read-Host

# -- 1. Define Download List (Array) --
$downloadList = @(
    @{ url = "https://download.cpuid.com/cpu-z/cpu-z_2.09-en.zip"; outputFolder = "$PSScriptRoot\Tools\Hardware\CPU-Z"; fileName="cpu-z.zip" },
    @{ url = "https://sourceforge.net/projects/crystaldiskinfo/files/9.2.3/CrystalDiskInfo9_2_3.zip/"; outputFolder = "$PSScriptRoot\Tools\Hardware\cystalDiskInfo"; fileName= "crystalDiskInfo.zip" },
    @{ url = "https://iperf.fr/download/windows/iperf-3.1.3-win64.zip"; outputFolder = "$PSScriptRoot\Tools\Networking\"; fileName= "iperf3.zip" },
    @{ url = "https://nmap.org/dist/nmap-7.92-win32.zip"; outputFolder = "$PSScriptRoot\Tools\Networking\"; fileName= "nmap.zip" },
    @{ url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"; outputFolder = "$PSScriptRoot\Tools\SysinternalsSuite"; fileName= "SysinternalsSuite.zip" },
    @{ url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"; outputFolder = "$PSScriptRoot\Tools\SysinternalsSuite"; fileName= "SysinternalsSuite.zip" },
    @{ url = "https://www.mark0.net/download/trid_w32.zip"; outputFolder = "$PSScriptRoot\Tools\windows\trid_w32"; fileName= "trid_w32.zip" },
    @{ url = "https://www.mark0.net/download/triddefs.zip"; outputFolder = "$PSScriptRoot\Tools\windows\trid_w32"; fileName= "triddefs.zip" }
    # Add more items in the format @{ url = ""; outputFolder = ""; fileName = ""  }
)

# -- 2. Process Downloads --
foreach ($item in $downloadList) {
    $zipFile = Join-Path $item.outputFolder $item.fileName

    # Create Directories if They Don't Exist
    if (!(Test-Path $item.outputFolder)) {
         New-Item -ItemType Directory -Path $item.outputFolder -Force
    }

    # Download the File
    Invoke-WebRequest  -UserAgent "Wget" -Uri $item.url -OutFile $zipFile
    #wget -O $fileName $

    # Unzip the Downloaded File (If applicable)
    if ($zipFile.ToLower().EndsWith(".zip")) {
        Expand-Archive -Path $zipFile -DestinationPath $item.outputFolder -Force
    }
    Start-Sleep -Milliseconds 300
    #Delete .Zip (Optional)
    if ($zipFile.ToLower().EndsWith(".zip")) {
        Remove-Item $zipFile
    } 
}

Read-Host  # Pause at the end 

