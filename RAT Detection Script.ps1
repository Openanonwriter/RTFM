# RAT Detection Script

# Check for suspicious scheduled tasks
function Check-ScheduledTasks {
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' }
    foreach ($task in $tasks) {
        Write-Host "Found suspicious task: $($task.TaskName)"
        # You can add additional checks or actions here
    }
}

# Check for suspicious processes
function Check-Processes {
    $suspiciousProcesses = @("rutserv.exe", "rfusclient.exe")
    $runningProcesses = Get-Process | Select-Object -ExpandProperty Name
    foreach ($process in $runningProcesses) {
        if ($suspiciousProcesses -contains $process) {
            Write-Host "Found suspicious process: $process"
            # You can add additional checks or actions here
        }
    }
}

# Main function
function Detect-RAT {
    Clear-Host
    Write-Host "=== RAT Detection Script ==="
    Write-Host "(1) Check Scheduled Tasks"
    Write-Host "(2) Check Running Processes"
    Write-Host "(Q) Quit"

    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        '1' {
            Check-ScheduledTasks
        }
        '2' {
            Check-Processes
        }
        'q' {
            Write-Host "Exiting..."
            return
        }
        default {
            Write-Host "Invalid choice. Please choose again."
            Detect-RAT
        }
    }
}

# Start the detection
Detect-RAT