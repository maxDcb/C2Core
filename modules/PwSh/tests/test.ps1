# Define a test function
function Get-ProcessInfo {
    Write-Host "=== Running Get-ProcessInfo ==="
    $process = Get-Process | Select-Object -First 1
    Write-Host "Process: $($process.ProcessName) - ID: $($process.Id)"
}

# Call the function
Get-ProcessInfo

# Set a variable and display it
$x = 42
Write-Host "`n=== Variable Test ==="
Write-Host "The value of x is: $x"

# Execute a standard command
Write-Host "`n=== Executing 'Get-Process' ==="
Get-Process | Select-Object -First 3
