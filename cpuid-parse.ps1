# Writen By Anthony Widick
# 3/26/26
# Script for parsing CPU-z Text file to to gather Power Infomation. (12v,5,3.3v rails)
# Windows fails to make this easily accesable. 
# Draft

# Specify the path to your input file
$filePath = "D:\RTFM\Tools\Hardware\cpu-z\report.txt"

$fileContent = Get-Content -Path $filePath -Raw 

# Initialize variables to store the extracted voltage data
$voltage_12v_data = $null
$voltage_3_3v_data = $null
$voltage_5v_data = $null

# Regular expressions with a capture group for the data before "Volts"
$regex_12v = '\w		(.+)\s+Volts.*\(\+12V\)'
$regex_3_3v = '\w		(.+)\s+Volts.*\(\+3\.3V\)'
$regex_5v = '\w		(.+)\s+Volts.*\(\+5V\)'

# Check for +12V
if ($fileContent -match $regex_12v) { 
    $voltage_12v_data = $Matches[1] # Capture the data before "Volts"
} 

# Check for +3.3V
if ($fileContent -match $regex_3_3v) { 
    $voltage_3_3v_data = $Matches[1] 
}

# Check for +5V       
if ($fileContent -match $regex_5v) { 
    $voltage_5v_data = $Matches[1]  
}

# Output the results
# Write-Output "Extracted voltage values:"
# Write-Output "+12V: $voltage_12v_data"
# Write-Output "+3.3V: $voltage_3_3v_data"
# Write-Output "+5V: $voltage_5v_data"

# # Nominal voltage values (adjust based on your ATX standard)
# $nominal_12v = 12
# $nominal_5v = 5
# $nominal_3_3v = 3.3

# # High and low voltage thresholds (calculated as 105% and 95% of nominal)
# $high_12v_threshold = $nominal_12v * 1.05
# $low_12v_threshold = $nominal_12v * 0.95
# $high_5v_threshold = $nominal_5v * 1.05
# $low_5v_threshold = $nominal_5v * 0.95
# $high_3_3v_threshold = $nominal_3_3v * 1.05
# $low_3_3v_threshold = $nominal_3_3v * 0.95

# # Output the results with voltage checks
# Write-Output "Extracted voltage values:"
# Write-Output "+12V: $voltage_12v_data"

# # Check for +12V out-of-range
# if ($voltage_12v_data -gt $high_12v_threshold -or $voltage_12v_data -lt $low_12v_threshold) {
#     Write-Output "WARNING: +12V out of range!"
#     [System.Console]::Beep(1000, 1000) # Beep for 1 second at 1000 Hz
#     Write-Output "**PSU Failure Likely!**"
# }

# Write-Output "+3.3V: $voltage_3_3v_data"

# # Check for +3.3V out-of-range
# if ($voltage_3_3v_data -gt $high_3_3v_threshold -or $voltage_3_3v_data -lt $low_3_3v_threshold) {
#     Write-Output "WARNING: +3.3V out of range!"
#     [System.Console]::Beep(500, 1000) # Beep for 1 second at 500 Hz
#     Write-Output "**PSU Failure Likely!**"
# }

# Write-Output "+5V: $voltage_5v_data"

# # Check for +5V out-of-range
# if ($voltage_5v_data -gt $high_5v_threshold -or $voltage_5v_data -lt $low_5v_threshold) {
#     Write-Output "WARNING: +5V out of range!"
#     [System.Console]::Beep(500, 1000) # Beep for 1 second at 500 Hz
#     Write-Output "**PSU Failure Likely!**"
# }
$nominal_voltages = @{
    "+12V" = 12
    "+5V" = 5
    "+3.3V" = 3.3
}

# Define voltage thresholds (105% and 95% of nominal)
function  get_voltage_thresholds($nominal_voltage) {
    $high_threshold = $nominal_voltage * 1.05
    $low_threshold = $nominal_voltage * 0.95
    return $high_threshold, $low_threshold
}

# Function to check voltage and display warnings/beeps
function  check_voltage($voltage_name, $voltage_data) {
    $high_threshold, $low_threshold = get_voltage_thresholds($nominal_voltages[$voltage_name])
    if ($voltage_data -gt $high_threshold -or $voltage_data -lt $low_threshold) {
        Write-Host "WARNING: $voltage_name out of range!" -ForegroundColor red
        [System.Console]::Beep(500, 1000)  # Beep for 1 second at 500 Hz
        Write-Host "**PSU Failure Likely!**" -ForegroundColor red
    }
}

$voltage_data = @{
    "+12V" = $voltage_12v_data
    "+5V" = $voltage_5v_data
    "+3.3V" = $voltage_3_3v_data
}

# Output and perform checks
Write-Output "Extracted voltage values:"
foreach ($voltage_name in $voltage_data.Keys) {
    $voltage_value = $voltage_data[$voltage_name] 
    Write-Output "$voltage_name : $voltage_value"
    check_voltage $voltage_name $voltage_value
}