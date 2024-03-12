$cdiskinfo="C:\Users\CrystalDiskInfo9_2_3"
& "$cdiskinfo\DiskInfo64.exe" /CopyExit
# Read the content of the text file (replace 'x.txt' with the actual file path)
$smartData = Get-Content -Path "C:\Users\DiskInfo.txt"

# Read the content of the text file (replace 'x.txt' with the actual file path)
# Flag to indicate whether we are within the S.M.A.R.T. section
$inSmartSection = $false
# Process each line in the file
foreach ($line in $smartData) {
    # Ignore empty lines and the line with 'ID RawValues(6) Attribute Name'
    if ([string]::IsNullOrWhiteSpace($line) -or $line -match "ID RawValues\(6\) Attribute Name") {
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
        Write-Host "-- IDENTIFY_DEVICE ---------------------------------------------------------"
        # Don't break here, as there might be more S.M.A.R.T. sections
        continue
    }

    if ($inSmartSection) {
        # Extract the relevant information (ID, RawValues, and Attribute Name)
        $columns = $line -split '\s+'
        $id = $columns[0]
        $rawValue = $columns[1]
        $attributeName = $columns[2,3,4,5,6,7,8]

        # Convert the hexadecimal string to a decimal number using BigInteger
        $decimalValue = [System.Numerics.BigInteger]::Parse($rawValue, [System.Globalization.NumberStyles]::HexNumber)

        # Display the result
        Write-Host "$id $decimalValue           $attributeName "
    } else {
        # If not in a S.M.A.R.T. section, just print the line
        Write-Host $line
    }
}
