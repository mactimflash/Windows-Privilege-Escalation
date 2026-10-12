<#
.SYNOPSIS
    Automated Windows Enumeration Script for Privilege Escalation Assessment (v6).
    Clean PowerShell syntax guaranteed.
#>

[CmdletBinding()]
param(
    [string]$OutFile = "$PSScriptRoot\enum_output.txt"
)

# Start logging transcript if possible
try {
    Start-Transcript -Path $OutFile -ErrorAction SilentlyContinue | Out-Null
} catch {}

function Write-SectionHeader {
    param ([string]$Title)
    $banner = "================================================================================"
    Write-Host "`n\$banner" -ForegroundColor Cyan
    Write-Host " [+] \$Title" -ForegroundColor Yellow
    Write-Host "\$banner`n" -ForegroundColor Cyan
}

function Invoke-SafeBlock {
    param (
        [string]$Name,
        [scriptblock]$ScriptBlock
    )
    Write-Host "---> Running Check: $Name" -ForegroundColor Green
    try {
        & $ScriptBlock
    } catch {
        Write-Host " [!] [ERROR] Failed to execute $Name : $_" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "================================================================================" -ForegroundColor Magenta
Write-Host "       WINDOWS AUTOMATED PRIVILEGE ESCALATION ENUMERATION SCRIPT (v6)           " -ForegroundColor Magenta
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Host "Execution Time : $(Get-Date)"
Write-Host "Output File    : $OutFile`n"

# ==========================================
# 1. Basic System & User Enumeration
# ==========================================
Write-SectionHeader "1. Basic System & User Enumeration"

Invoke-SafeBlock "Current User Context & Privileges" {
    whoami /all
}

Invoke-SafeBlock "Local Users Summary" {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Format-Table -AutoSize
    } else {
        net user
    }
}

Invoke-SafeBlock "Local Groups Summary" {
    if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {
        Get-LocalGroup | Format-Table -AutoSize
    } else {
        net localgroup
    }
}

Invoke-SafeBlock "Administrators Group Members" {
    try {
        Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Format-Table -AutoSize
    } catch {
        net localgroup Administrators
    }
}

Invoke-SafeBlock "System Information Summary" {
    systeminfo
}

# ==========================================
# 2. Network Enumeration
# ==========================================
Write-SectionHeader "2. Network Configuration & Active Connections"

Invoke-SafeBlock "IP Configuration" {
    ipconfig /all
}

Invoke-SafeBlock "Routing Table" {
    route print
}

Invoke-SafeBlock "Active Network Connections & Listening Ports" {
    netstat -ano
}

# ==========================================
# 3. Installed Applications & Running Processes
# ==========================================
Write-SectionHeader "3. Software & Running Processes"

Invoke-SafeBlock "Installed 32-bit Software (Registry)" {
    Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Get-ItemProperty -ErrorAction SilentlyContinue |
        Where-Object { \$_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Sort-Object DisplayName |
        Format-Table -AutoSize
}

Invoke-SafeBlock "Installed 64-bit Software (Registry)" {
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Get-ItemProperty -ErrorAction SilentlyContinue |
        Where-Object { \$_.DisplayName } |
        Sort-Object DisplayName |
        Format-Table -AutoSize
}

Invoke-SafeBlock "Running Processes" {
    Get-Process | Select-Object Id, ProcessName, Path | Format-Table -AutoSize
}

# ==========================================
# 4. Sensitive Files & Credentials Search
# ==========================================
Write-SectionHeader "4. Searching Sensitive Files & Credentials"

Invoke-SafeBlock "KeePass Databases (*.kdbx)" {
    Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
}

Invoke-SafeBlock "Configuration Files in Common Directories (e.g. XAMPP)" {
    if (Test-Path "C:\xampp") {
        Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
    } else {
        Write-Host "C:\xampp does not exist."
    }
}

Invoke-SafeBlock "User Document Files (*.txt, *.pdf, *.xls, *.xlsx, *.doc, *.docx)" {
    \$userPath = "C:\Users\"
    Get-ChildItem -Path \$userPath -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        Select-Object -First 50
}

# ==========================================
# 5. PowerShell History & Transcripts
# ==========================================
Write-SectionHeader "5. PowerShell History & Transcript Logs"

Invoke-SafeBlock "Session History" {
    Get-History
}

Invoke-SafeBlock "PSReadLine History File" {
    try {
        \$historyPath = (Get-PSReadlineOption).HistorySavePath
        Write-Host "PSReadLine History Path: \$historyPath"
        if (Test-Path \$historyPath) {
            Get-Content \$historyPath -ErrorAction SilentlyContinue
        } else {
            Write-Host "History file does not exist at path."
        }
    } catch {
        Write-Host "Unable to retrieve PSReadLine option."
    }
}

Invoke-SafeBlock "Public PowerShell Transcripts" {
    \$transcriptDir = "C:\Users\Public\Transcripts"
    if (Test-Path \$transcriptDir) {
        Get-ChildItem -Path \$transcriptDir -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "--- Content of: \\((\\)_.FullName) ---"
            Get-Content \$_.FullName -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Directory C:\Users\Public\Transcripts does not exist."
    }
}

# ==========================================
# 6. Windows Services & Unquoted Service Paths
# ==========================================
Write-SectionHeader "6. Windows Services & Vulnerable Service Paths"

Invoke-SafeBlock "Running Windows Services & Executable Paths" {
    try {
        Get-CimInstance -ClassName win32_service -ErrorAction Stop |
            Select-Object Name, State, StartMode, PathName |
            Where-Object { \$_.State -eq 'Running' } |
            Format-Table -AutoSize
    } catch {
        Write-Host "[!] Get-CimInstance failed (possibly network logon or WMI access denied). Falling back to sc.exe query..." -ForegroundColor Yellow
        sc.exe query type= service state= all
    }
}

Invoke-SafeBlock "Unquoted Service Paths Check (Pure PowerShell)" {
    Get-CimInstance -ClassName win32_service -ErrorAction SilentlyContinue |
        Where-Object {
            \\(_.PathName -and 
            \\)_.PathName -notmatch '^\s*"' -and 
            \\(_.PathName -like '* *' -and 
            \\)_.PathName -notlike 'C:\Windows\*'
        } |
        Select-Object Name, DisplayName, PathName, StartMode, State |
        Format-Table -AutoSize
}

# ==========================================
# 7. Scheduled Tasks & Security Hotfixes
# ==========================================
Write-SectionHeader "7. Scheduled Tasks & Installed Hotfixes"

Invoke-SafeBlock "Installed Security Updates (Hotfixes)" {
    try {
        Get-CimInstance -Class win32_quickfixengineering -ErrorAction Stop |
            Where-Object { \$_.Description -eq "Security Update" -or \$_.HotFixID } |
            Select-Object HotFixID, Description, InstalledOn |
            Format-Table -AutoSize
    } catch {
        Get-HotFix -ErrorAction SilentlyContinue | Format-Table -AutoSize
    }
}

Invoke-SafeBlock "Scheduled Tasks Summary" {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        Get-ScheduledTask | Where-Object { \$_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, State | Select-Object -First 40 | Format-Table -AutoSize
    } else {
        schtasks /query /fo LIST /v
    }
}

# Stop transcript if running
try {
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
} catch {}

Write-Host "================================================================================" -ForegroundColor Green
Write-Host " Enumeration Complete! Results written to console and '\$OutFile'" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
