function New-PowerShellRunnerHeader
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $AssemblyPath
    )
	
	write-output $AssemblyPath
	$Bytes = Get-Content -Raw -Encoding Byte $AssemblyPath
	$OutputStr = New-Object System.Text.StringBuilder
	
	write-output $OutputStr

	$Counter = 1
	foreach($Byte in $Bytes) {
		$null = $OutputStr.Append("0x$('{0:X2}' -f $Byte),") 

		if($Counter % 12 -eq 0) {
			$null = $OutputStr.AppendLine()
			$null = $OutputStr.Append("`t")
		}
		$Counter++
	}

	$null = $OutputStr.Remove($OutputStr.Length-1,1)

	$Source = @"
#ifndef POWERSHELLRUNNERDLL_H_
#define POWERSHELLRUNNERDLL_H_

static const unsigned char PowerShellRunner_dll[] = {
    $($OutputStr.ToString())
};

static const unsigned int PowerShellRunner_dll_len = $($Bytes.Length);

#endif
"@

	$Source | Out-File -FilePath header.h
}

New-PowerShellRunnerHeader .\PowerShellRunner.dll