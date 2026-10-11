<#
.SYNOPSIS
    Automated Windows Enumeration Script for Privilege Escalation Assessment.
#>

[CmdletBinding()]
param(
    [string]$OutFile = "$PSScriptRoot\enum_output.txt"
)

# Khởi tạo ghi log ra file
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
Write-Host "       WINDOWS AUTOMATED PRIVILEGE ESCALATION ENUMERATION SCRIPT                " -ForegroundColor Magenta
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
    Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object { \$_.DisplayName } |
        Format-Table -AutoSize
}

Invoke-SafeBlock "Installed 64-bit Software (Registry)" {
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object { \$_.DisplayName } |
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
    \\(userPath = "\\)env:SystemDrive\Users\"
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
        Write-Host "[!] Get-CimInstance failed (Access Denied / Network Shell). Falling back to sc.exe query..." -ForegroundColor Yellow
        sc.exe query type= service state= all
    }
}

Invoke-SafeBlock "Unquoted Service Paths Check" {
    cmd.exe /c 'wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """'
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

# Dừng transcript
try {
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
} catch {}

Write-Host "================================================================================" -ForegroundColor Green
Write-Host " Enumeration Complete! Results written to console and '\$OutFile'" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
