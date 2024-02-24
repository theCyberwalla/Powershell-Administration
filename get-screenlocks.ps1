# Function to get events from Windows Event Log
function Get-UserLockUnlockEvents {
    param(
        [string]$logName = "Security",
        [int]$eventIdLock = 4800,  # Event ID for workstation lock
        [int]$eventIdUnlock = 4801,  # Event ID for workstation unlock
        [int]$maxEvents = 50  # Maximum number of events to retrieve
    )

    # Construct filter XPath query
    $filterXPath = "*[System[EventID=$eventIdLock or EventID=$eventIdUnlock]]"

    # Query the Windows Event Log
    $events = Get-WinEvent -LogName $logName -MaxEvents $maxEvents | Where-Object { $_.Id -eq $eventIdLock -or $_.Id -eq $eventIdUnlock }

    # Output events
    foreach ($event in $events) {
        $time = $event.TimeCreated
        $action = if ($event.Id -eq $eventIdLock) { "Locked" } else { "Unlocked" }
        $user = $event.Properties[1].Value

        Write-Output "$time - $user $action the workstation"
    }
}

# Call the function to get lock and unlock events
Get-UserLockUnlockEvents
