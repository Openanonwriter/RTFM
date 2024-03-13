$currentDirectory = $PSScriptRoot

$cdiskinfo = Get-ChildItem -Path $currentDirectory -Filter DiskInfo64.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
& "$cdiskinfo" /CopyExit
$diskinfoPath = Get-ChildItem -Path $currentDirectory -Filter DiskInfo.txt -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
$smartData = Get-Content -Path $diskinfoPath
# Read the content of the text file (replace 'x.txt' with the actual file path)
# Flag to indicate whether we are within the S.M.A.R.T. section
$inSmartSection = $false
$unneeded0 = '-- SMART_NVME --------------------------------------------------------------'
$unneeded1 = "        0    1    2    3    4    5    6    7    8    9"
$unneeded2 = '     \+0 \+1 \+2 \+3 \+4 \+5 \+6 \+7 \+8 \+9 \+A \+B \+C \+D \+E \+F'
$unneeded3 = 'Write-Host "ID Cur Wor Thr RawValues(6) Attribute Name"'
# Process each line in the file
if ($smartData -eq '-- SMART_READ_THRESHOLD ----------------------------------------------------'){
foreach ($line in $smartData) {
# Ignore empty lines and the line with 'ID RawValues(6) Attribute Name'
if ([string]::IsNullOrWhiteSpace($line) -or $line -match 'ID Cur Wor Thr RawValues(6) Attribute Name') {
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
    Write-Host "----------------------------------------------------------------------------"
    # Don't break here, as there might be more S.M.A.R.T. sections
    continue
}

if ($inSmartSection) {
    # Extract the relevant information (ID, RawValues, and Attribute Name)
    $columns = $line -split '\s+'
    $id = $columns[0]
    $rawValue = $columns[4]
    #$attributeName = $columns[6,7,8,7,8,9]
    # Convert the hexadecimal string to a decimal number using BigInteger
    $decimalValue = [System.Numerics.BigInteger]::Parse($rawValue, [System.Globalization.NumberStyles]::HexNumber)

    # Display the result
    Write-Host "$id $decimalValue"           #$attributeName "
} elseif (-not ($line -match "^($unneeded3|000:|010:|020:|0AE:|030:|040:|050:|060:|070:|080:|090:|100:|110:|120:|130:|140:|150:|160:|170:|180:|190:|200:|210:|220:|230:|240:|250:|1A0:|0A0:|0B0:|0D0:|1B0:|1C0:|0E0:|0C0:|0F0:|1E0:|1D0:|1F0:|$unneeded0|$unneeded1|$unneeded2)")) {        # If not in a S.M.A.R.T. section and not a filtered line, print the line
    Start-Sleep -Milliseconds 10
    Write-Host $line
    Clear-Variable -name cdiskinfo
    }
}
}

