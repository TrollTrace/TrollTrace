# Define the log file path
$logFile = "C:\path\to\output\log.txt"

# Run the commands and capture the output
$authFailures = Get-Content -Path "C:\path\to\auth.log" | Select-String -Pattern "authentication failure"
$acceptedSSH = Get-Content -Path "C:\path\to\auth.log" | Select-String -Pattern "sshd.*Accepted"

# Output the data to the log file
$authFailures | Out-File -FilePath $logFile -Append
$acceptedSSH | Out-File -FilePath $logFile -Append

Write-Output "Log entries have been written to $logFile"
