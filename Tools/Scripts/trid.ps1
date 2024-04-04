Add-Type -AssemblyName System.Windows.Forms
$parentDirectory = Split-Path -Parent $PSScriptRoot 
$PSTrid_32Path = Get-ChildItem -Path $parentDirectory -Filter trid.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
$initialDirectory = [Environment]::GetFolderPath('User')
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.InitialDirectory = $initialDirectory
$OpenFileDialog.Multiselect = $false
$response = $OpenFileDialog.ShowDialog( ) # $response can return OK or Cancel
if ( $response -eq 'OK' ) { 
    Write-host $PSTrid_32Path
    & $PSTrid_32Path  $OpenFileDialog.FileName  
}
break