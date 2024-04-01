# Writen by Anthony Widick, released under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
    Clear-Host
    # Powershell script to run sfc first, then run dism if sfc shows "Windows Resource Protection found corrupt files and successfully repaired them.", then sfc a second time.

    # Run sfc first and capture output
    Write-Host "Running sfc.exe..."
    Write-Host $sfcOutput
    $sfcOutput = sfc.exe /scannow 2>&1 | Tee-Object -Variable sfcResults
    
    # Check if sfc reported successful repair
    if ($sfcOutput -match "Windows Resource Protection found corrupt files and successfully repaired them.") {
        Write-Host "SFC detected and repaired corrupt files. Running DISM..."

        # Run DISM
        dism.exe /online /cleanup-image /restorehealth 2>&1 | ForEach-Object { Write-Host $_; $_ } | Tee-Object -Variable dismResults
        Write-Host $dismResults
        Write-Host "DISM completed. Running sfc again..."

        # Run sfc again
        sfc.exe /scannow 2>&1 | ForEach-Object { Write-Host $_; $_ } | Tee-Object -Variable sfcResults
    }
    else {
($sfcOutput -match "Windows Resource Protection did not find any integrity violations." )
        Write-Host "Windows Resource Protection did not find any integrity violations."
    }
    Write-Host "DISM and SFC completed" -ForegroundColor Magenta

    switch ($subChoice) {
        'q' { break }
        default {
            Write-Host "Invalid selection. Please choose again."
            Read-Host
        }
    }
