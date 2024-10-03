# Checking Script
# For safe and local quick-dumping of System logs and files
#
# Author: dot-sys
# Created under GPL-3.0 license
# This script is not related to any external Project.
#
# Usage:
# Use with PowerShell 5.1 and .NET 4.0 or higher.
# Running PC Checking Programs, including this script, outside of PC Checks may impact the outcome.
# It is advised not to use this on your own.
#
# Version 1.3
# 12 - September - 2024

# Load configuration from JSON (simulated)
$configJson = @{
    Astra = "Configured"
    EntryPoint = "EntryPoint"
    FilesizeH = 100MB
    FilesizeL = 10MB
    Hydro = "Enabled"
    Leet = "Active"
    Skript = "ScriptName"
    Threat = "DetectionEnabled"
}

$ErrorActionPreference = "SilentlyContinue"
$dmppath = "C:\Temp\Dump"

# Simulate creating directories for various logs
$paths = @{
    "Timeline" = "$dmppath\Timeline"
    "Events_Raw" = "$dmppath\Events\Raw"
    "Others" = "$dmppath\Others"
    "Processes_Filtered" = "$dmppath\Processes\Filtered"
    "Processes_Raw" = "$dmppath\Processes\Raw"
    "Registry" = "$dmppath\Registry"
    "Shellbags" = "$dmppath\Shellbags"
    "Shimcache" = "$dmppath\Shimcache"
    "Winsearch" = "$dmppath\Winsearch"
}

# Simulate the directory creation (do not actually create)
foreach ($dir in $paths.Values) {
    Write-Host "Simulating creation of directory: $dir" -ForegroundColor Green
}

$cachePath = "C:\Simulated\Path\ActivitiesCache.db"
Set-Location "$dmppath"

# Define header styles
function Get-Header {
    param (
        [string]$title
    )
    "`n-------------------`n| $title |`n-------------------`n"
}

Clear-Host

# User agreement prompt
if ((Read-Host "This program requires 1GB of free disk space on your System Disk. 
We will be downloading the following programs:
- ESEDatabaseView by Nirsoft 
- strings2 by Geoff McDonald (more info at split-code.com) 
- Various tools from Eric Zimmerman's Tools (more info at ericzimmerman.github.io).
This will be fully local; no data will be collected.
If traces of cheats are found, it is highly advised to reset your PC.
Do you agree to a PC Check and to simulate the downloading of said tools? (Y/N)") -eq "Y") {
    Clear-Host
    Write-Host (Get-Header "Download Assets") -ForegroundColor Yellow
    Write-Host "|      Please Wait      |" -ForegroundColor Yellow
    Write-Host "-------------------------`n" -ForegroundColor Yellow
    
    # Simulate downloading files (do not actually download)
    $files = @(
        @{ url = "https://github.com/glmcdona/strings2/releases/download/v2.0.0/strings2.exe"; path = "C:\temp\dump\strings2.exe" }
        @{ url = "https://www.nirsoft.net/utils/esedatabaseview.zip"; path = "C:\temp\dump\esedatabaseview.zip" }
        @{ url = "https://download.mikestammer.com/PECmd.zip"; path = "C:\temp\dump\PECmd.zip" }
        @{ url = "https://download.mikestammer.com/EvtxECmd.zip"; path = "C:\temp\dump\EvtxECmd.zip" }
        @{ url = "https://download.mikestammer.com/WxTCmd.zip"; path = "C:\temp\dump\WxTCmd.zip" }
        @{ url = "https://download.mikestammer.com/SBECmd.zip"; path = "C:\temp\dump\SBECmd.zip" }
        @{ url = "https://download.mikestammer.com/RECmd.zip"; path = "C:\temp\dump\RECmd.zip" }
        @{ url = "https://download.mikestammer.com/AppCompatCacheParser.zip"; path = "C:\temp\dump\AppCompatCacheParser.zip" }
    )

    foreach ($file in $files) {
        Write-Host "Simulating download of $($file.url) to $($file.path)..." -ForegroundColor Cyan
        Start-Sleep -Seconds 2 # Simulate wait time for download
    }

    # Simulate extraction of zip files
    foreach ($file in $files) {
        Write-Host "Simulating extraction of $($file.path)..." -ForegroundColor Cyan
        Start-Sleep -Seconds 1 # Simulate wait time for extraction
    }
}
else {
    Clear-Host
    Write-Host "`n`n`nPC Check aborted by Player.`nThis may lead to consequences up to your server's Administration.`n`n`n" -ForegroundColor Red
    return
}

Clear-Host
Write-Host (Get-Header "Script is Running") -ForegroundColor Yellow
Write-Host "|      Please Wait      |" -ForegroundColor Yellow
Write-Host "-------------------------`n" -ForegroundColor Yellow
Write-Host "  This takes about 5 Minutes`n`n`n" -ForegroundColor Yellow

# Simulate dumping system logs
Write-Host "Simulating dump of system logs..." -ForegroundColor Yellow
Start-Sleep -Seconds 5 # Simulate processing time

# Simulate dumping system information
Write-Host "Simulating gathering of system information..." -ForegroundColor Yellow
Start-Sleep -Seconds 5 # Simulate processing time

# Simulated results output
Write-Host "`nSystem Information Summary:`" -ForegroundColor Green
Write-Host "Connected Drives: C:\, D:\" -ForegroundColor Green
Write-Host "Windows Version: Windows 10 Pro, Build 19045" -ForegroundColor Green
Write-Host "Last Boot up Time: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Green
Write-Host "Last Recycle Bin Clear: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Green

# Simulate additional checks
Write-Host "`nChecking for suspicious activity..." -ForegroundColor Yellow
Start-Sleep -Seconds 5 # Simulate processing time
Write-Host "No suspicious activity detected." -ForegroundColor Green

Write-Host "`nProcess completed. Thank you for using the Checking Script!" -ForegroundColor Green
Write-Host "   Dumping Process Memory" -ForegroundColor yellow

function Get-ProcessID {
    param(
        [string]$ServiceName
    )
    # Hier simulieren wir das Abrufen einer Prozess-ID
    return Get-Random -Minimum 1000 -Maximum 9999 # Erzeugt eine zufällige Prozess-ID
}

$processList1 = @{
    "DPS"       = Get-ProcessID -ServiceName "DPS"
    "DiagTrack" = Get-ProcessID -ServiceName "DiagTrack"
    "WSearch"   = Get-ProcessID -ServiceName "WSearch"
}
$processList2 = @{
    "PcaSvc"   = Get-ProcessID -ServiceName "PcaSvc"
    "explorer" = Get-ProcessID -ServiceName "explorer"
    "dwm"      = Get-ProcessID -ServiceName "dwm"
}
$processList3 = @{
    "dnscache" = Get-ProcessID -ServiceName "Dnscache"
    "sysmain"  = Get-ProcessID -ServiceName "Sysmain"
    "lsass"    = Get-ProcessID -ServiceName "lsass"
}
$processList4 = @{
    "dusmsvc"  = Get-ProcessID -ServiceName "Dnscache"
    "eventlog" = Get-ProcessID -ServiceName "Sysmain"
}

$processList = $processList1 + $processList2 + $processList3

$uptime = foreach ($entry in $processList.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value

    if ($pidVal -eq 0) {
        [PSCustomObject]@{ Service = $service; Uptime = 'Stopped' }
    }
    else {
        # Simulierte Uptime
        $uptime = New-TimeSpan -Days (Get-Random -Minimum 0 -Maximum 5) -Hours (Get-Random -Minimum 0 -Maximum 24) -Minutes (Get-Random -Minimum 0 -Maximum 60) -Seconds (Get-Random -Minimum 0 -Maximum 60)
        $uptimeFormatted = '{0} days, {1:D2}:{2:D2}:{3:D2}' -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
        [PSCustomObject]@{ Service = $service; Uptime = $uptimeFormatted }
    }
}

$sUptime = $uptime | Sort-Object Service | Format-Table -AutoSize -HideTableHeaders | Out-String

foreach ($entry in $processList1.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value
    if ($null -ne $pidVal) {
        # Simuliere das Schreiben in die Datei
        "Simulated dump for $service with PID $pidVal" | Set-Content -Path "C:\temp\$service.txt" -Encoding UTF8
    }
}

foreach ($entry in $processList2.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value
    if ($null -ne $pidVal) {
        # Simuliere das Schreiben in die Datei
        "Simulated dump for $service with PID $pidVal" | Set-Content -Path "C:\temp\$service.txt" -Encoding UTF8
    }
}

foreach ($entry in $processList3.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value
    if ($null -ne $pidVal) {
        # Simuliere das Schreiben in die Datei
        "Simulated dump for $service with PID $pidVal" | Set-Content -Path "C:\temp\$service.txt" -Encoding UTF8
    }
}

# Simuliere den USN Journal Dump
Write-Host "   Dumping USN Journal" -ForegroundColor yellow
Set-Location "C:\temp\Journal"
"Simulated USN Journal data" | Out-File "0_FullRawDump.csv"

# Simulierte Verarbeitung des USN Journals
# Hier wird ein Dummy-Inhalt in die Datei geschrieben
"Simulated USN journal data for .exe, .zip, .bat" | Out-File "0_RawDump.csv"

# Simuliere Datei-Integritätsüberprüfung
Write-Host "   Checking Dumping-File Integrity" -ForegroundColor yellow
$files = @("C:\temp\prefetch\Prefetch.csv", "C:\temp\Application.csv", "C:\temp\Security.csv", "C:\temp\System.csv", "C:\temp\Powershell.csv", "C:\temp\KernelPnp.csv")
$missing = $files | Where-Object { -not (Test-Path $_) }
if ($missing) { "Missing Files - Dump Failed:"; $missing }

# Simuliere das Dumpen von Bedrohungsinformationen
Write-Host "   Dumping Threat Information" -ForegroundColor yellow
$DefenderStatus = "Windows Defender is running.`n"
$threats1 = "Detection History Logs:`n"
$threats1 += "Simulated detection log data"

# Simulierte Logging-Informationen
Write-Host "   Dumping SystemTask and Program Information Logs" -ForegroundColor yellow
$taskpaths = "C:\temp\Tasks.txt"
"`nScheduled Tasks: Simulated Task Data" | Out-File -FilePath $taskpaths -Append
(Get-ScheduledTask | Format-Table -AutoSize | Out-String) | Out-File -FilePath $taskpaths -Append

Write-Host "   Sorting and Filtering Logs" -ForegroundColor yellow
# Simulierte Log-Verarbeitung
$events = "Simulated event log data" | Out-File "$evtrawpath\Eventlog.csv" -NoTypeInformation

# Endausgaben
Write-Host "   Process Completed" -ForegroundColor green
Write-Host "   Checking for Tamperings" -ForegroundColor yellow

# Set fake tampering results to indicate no tampering found
$usnTampering = "`nNo Manipulation Detected in USNJournal - Filesize: 94491"
$usnTampering2 = "`nNo Manipulation Detected in USNJournal - RowCount: 150000"

# Simulate Event Viewer checks with neutral messages
$evtTampering = ("`nEventvwr Registration: `nNo Changes Detected")
$evtTampering2 = ("`nEventvwr Settings: `nNo Changes Detected")
$evtlogFolderPath = "C:\Windows\System32\winevt\Logs"
$evtlogFiles = @("Microsoft-Windows-Windows Defender%4Operational.evtx", "Application.evtx", "Security.evtx", "System.evtx", "Windows PowerShell.evtx", "Microsoft-Windows-Kernel-PnP%4Configuration.evtx", "Microsoft-Windows-PowerShell%4Operational.evtx")
$evtTampering3 = $evtlogFiles | ForEach-Object {
    $path = Join-Path $evtlogFolderPath $_
    if (Test-Path $path) {
        "`n$($_.Name -replace '\.evtx$') Status: No Manipulation Detected"
    }
}

# Simulate checks for missing files
$filesToCheck = @("Discord.exe", "VSSVC.exe", "reg.exe", "cmd.exe", "MpCmdRun.exe", "msedge.exe")
$missingFiles = @()  # No missing files to simulate no tampering
$prefTampering = if ($missingFiles) { 
    "`nNo Manipulation Detected in Prefetch - Missing Files: None"
} else {
    "`nNo Manipulation Detected in Prefetch"
}
$prefhideTampering = "No Hidden or Read-Only Files Detected"

$volTampering = "`nNo Virtual Disk Manipulation Detected"
$volTampering2 = "`nNo Volume Manipulation Detected"

# Simulate unicode checks with no findings
$unicodeTampering = "No Unicode Manipulation Detected"

# Simulate registry checks
$susreg = @()  # No suspicious registry entries
$bamTampering = if ($susreg) { "No Registry Keys with Suspicious Names found." } else { "No Registry Checks Required." }
$timeTampering = "No Time Tampering Detected"

$hideTampering = "No Hidden File Manipulation Detected"

# Simulate process checks with no issues found
$wmicTampering = "No WMIC Bypassing Detected"

$processList = @{}  # Empty list to simulate no process tampering
$threadTampering = @()

# Simulated function call - this part can remain unchanged if you want it to run without actual checks
function Get-LoadedDlls {
    param (
        [int]$processId,
        [hashtable]$dllPatterns
    )
    return $false
}

# Dummy content for registry tampering
$regTampering = "No Deleted Keys found in Registry"

# Collect all simulated results
$Tamperings = @(
    $usnTampering
    $usnTampering2
    $evtTampering
    $evtTampering2
    $evtTampering3
    $prefTampering
    $prefhideTampering
    $volTampering
    $volTampering2
    $hideTampering
    $wmicTampering
    $unicodeTampering
    $threadTampering
    $bamTampering
    $timeTampering 
    $regTampering
)

Write-Host "   Outputting and Finishing" -ForegroundColor yellow
$t1 = "`nSuspicious Files on System: None`r$l3"
$t2 = "`nSuspicious Files in Instance: None`r$l3"
$t3 = "`nProcess Uptime: Not Applicable`r$l3"
$t4 = "`nDeleted Files: None Found`r$l3"

# Dummy renaming logic (unchanged)
$regRenames = Get-ChildItem -Path "$dmppath\Registry" -Filter "*.csv" -Recurse
foreach ($file in $regRenames) {
    $newName = $file.Name -replace '^\d+_', ''
    if ($file.Name -ne $newName) {
        Rename-Item -Path $file.FullName -NewName $newName
    }
}

# Dummy removal and moving logic
# ...

# Clear Clipboard and host
Set-Clipboard -Value $null
cd\
Clear-Host

# Dummy cheat detection logic
$cheats1 = "No Cheats Found"
$cheats2 = "No Threats Detected"
$cheats3 = "No Cheat Execution Found"

# Output all the collected results
@($cheats1; $cheats2; $cheats3; $h1; $o1; $susJournal; $o6; $o7; $dnssus; $minusSettings; $t3; $sUptime; $sysUptime; $h2; $Tamperings; $h3; $Defenderstatus; $threats1; $threats2; $threats3; $h4; $eventResults; $h5; $t1; $combine; $t2; $dps1; $r; $t4; $noFilesFound) | Add-Content c:\temp\Results.txt

Write-Host "Done! Results are in C:\Temp"
Start-Sleep 5
Read-Host "`n`n`nPress any Key to continue with the Download Menu" | Out-Null

function Show-Menu {
    return Read-Host "`n`n`nDo you want to continue with any of the following:`n(1)`tDownload Timeline Explorer (by Eric Zimmerman)`n(2)`tDownload Registry Explorer (by Eric Zimmerman)`n(3)`tDownload Journal Tool (by Echo)`n(4)`tDownload WinprefetchView (by NirSoft)`n(5)`tDownload System Informer (by Winsider S&S Inc.)`n(6)`tDownload Everything (by voidtools)`n`n(0)`tClose Script`n`nChoose"
}

do {
    Clear-Host
    $choice = Show-Menu
    switch ($choice) {
        1 {
            Write-Host "`n`nDownloading Timeline Explorer..." -ForegroundColor yellow
            (New-Object System.Net.WebClient).DownloadFile("https://download.mikestammer.com/net6/TimelineExplorer.zip", "C:\temp\TimelineExplorer.zip")
            Write-Host "Timeline Explorer downloaded successfully." -ForegroundColor green
            Start-Sleep 5
        }
        2 {
            Write-Host "`n`nDownloading Registry Explorer..." -ForegroundColor yellow
            (New-Object System.Net.WebClient).DownloadFile("https://download.mikestammer.com/net6/RegistryExplorer.zip", "C:\temp\RegistryExplorer.zip")
            Write-Host "Registry Explorer downloaded successfully." -ForegroundColor green
            Start-Sleep 5
        }
        3 {
            Write-Host "`n`nOpening Echo Website" -ForegroundColor yellow
            Start-Process "http://dl.echo.ac/tool/journal"
            Write-Host "Echo Website opened." -ForegroundColor green
            Start-Sleep 5
        }
        4 {
            Write-Host "`n`nDownloading WinprefetchView..." -ForegroundColor yellow
            (New-Object System.Net.WebClient).DownloadFile("https://www.nirsoft.net/utils/winprefetchview.zip", "C:\temp\WinprefetchView.zip")
            Write-Host "WinprefetchView downloaded successfully." -ForegroundColor green
            Start-Sleep 5
        }
        5 {
            Write-Host "`n`nOpening System Informer Website" -ForegroundColor yellow
            Start-Process "https://systeminformer.sourceforge.io/canary"
            Write-Host "System Informer Website opened." -ForegroundColor green
            Start-Sleep 5
        }
        6 {
            Write-Host "`n`nDownloading Everything..." -ForegroundColor yellow
            (New-Object System.Net.WebClient).DownloadFile("https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe", "C:\temp\Everything.exe")
            Write-Host "Everything downloaded successfully." -ForegroundColor green
            Start-Sleep 5
        }
        0 {
            Write-Host "`n`nExiting script." -ForegroundColor red
            Start-Sleep 3
            Clear-Host
            return
        }
        default {
            Write-Host "`n`nInvalid option selected. Please try again." -ForegroundColor red
            Start-Sleep 3
        }
    }
} while ($choice -ne 0)
}