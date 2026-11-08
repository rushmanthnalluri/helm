<#
.SYNOPSIS
    Installs Homie desktop assistant and creates Windows shortcuts.
#>

$ErrorActionPreference = "Stop"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "         Installing Homie for Windows    " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[✓] Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "Python is not installed or not in your PATH. Please install Python 3.10+."
    exit 1
}

# 2. Check Claude Code CLI
$claudePath = Get-Command claude -ErrorAction SilentlyContinue
if ($claudePath) {
    Write-Host "[✓] Found Claude Code CLI: $($claudePath.Source)" -ForegroundColor Green
} else {
    Write-Host "[!] Note: Claude CLI ('claude') not found in PATH." -ForegroundColor Yellow
    Write-Host "    Install via: npm install -g @anthropic-ai/claude-code" -ForegroundColor Yellow
    Write-Host "    Instant local commands will still work without AI." -ForegroundColor Yellow
}

# 3. Install requirements
$homieDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $homieDir

Write-Host "`n[*] Installing required Python packages..." -ForegroundColor Cyan
python -m pip install -r requirements.txt

# 4. Create Desktop Shortcut
Write-Host "`n[*] Creating Desktop and Start Menu shortcuts..." -ForegroundColor Cyan
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktopPath "Homie.lnk"
    $shortcut = $WshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $homieDir "run.bat"
    $shortcut.WorkingDirectory = $homieDir
    $shortcut.IconLocation = Join-Path $homieDir "ui\AppIcon.ico"
    $shortcut.Description = "Homie - Voice AI Assistant for Windows"
    $shortcut.Save()
    Write-Host "[✓] Created Desktop Shortcut: $shortcutPath" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not create desktop shortcut: $_" -ForegroundColor Yellow
}

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "   Homie is ready to roll!" -ForegroundColor Green
Write-Host "   Launch with: .\run.bat or the Desktop shortcut" -ForegroundColor Green
Write-Host "   Shortcut: Hold Ctrl+Alt+Space, talk, let go" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
