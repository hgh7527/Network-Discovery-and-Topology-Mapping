# Define parameters
$Threshold = 5 #how many failed login attempts from same ip address 
$TimeRange = (Get-Date).AddMinutes(-10) # Gets the current time and then subtracts 10 minutes so just working with last 10 minutes 

# Fetch failed login attempts
Write-Output "`nChecking for failed logins" #message 
$failedLogins = Get-WinEvent -FilterHashtable @{ # searches windows event log for events matching below 
    LogName   = 'Security'
    ID        = 4625 # event ID
    StartTime = $TimeRange
} | Select-Object TimeCreated, Message #extracts just the timestamp and the event message which contains login details 

# Parse logs and extract source IPs
$ipCounts = @{} # empty hashtable 
foreach ($event in $failedLogins) {
    #loop through failed login counts 
    if ($event.Message -match 'Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)') {
        # searches the event messgae for ip with regular expression
        $ip = $matches[1] # stores ip 
        $ipCounts[$ip] = ($ipCounts[$ip] + 1) # increments a counts 
    }
}

# Check for IPs exceeding
foreach ($ip in $ipCounts.Keys) {
    # this will check how many times failed and see if it exceeds the threshold
    if ($ipCounts[$ip] -ge $Threshold) {
        Write-Host "$ip has failed $($ipCounts[$ip]) times" # if so it will alert you 
    }
}

# Check for privileged logins
Write-Output "`nLooking for privileged logins"
$privilegedLogins = Get-WinEvent -FilterHashtable @{ #searches for privileged login attempts 
    LogName   = 'Security'
    ID        = 4672 # event id for user logs with special
    StartTime = $TimeRange
} | Select-Object TimeCreated, Message

if ($privilegedLogins) {
    # if any where found it will warn
    Write-Host "Privileged account logins that are suspicious:"
    $privilegedLogins | ForEach-Object { Write-Host $_.TimeCreated $_.Message } # if none 
}
else {
    Write-Output "No privileged logins in this timeframe."
}