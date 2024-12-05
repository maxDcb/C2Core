# Define the PrintHelloWorld function
function PrintHelloWorld {
    Write-Output "Hello, World!"
}

# Export the function to make it available to other scripts
Export-ModuleMember -Function PrintHelloWorld
