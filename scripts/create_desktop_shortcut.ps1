$desktop = [Environment]::GetFolderPath('Desktop')
$wsh = New-Object -ComObject WScript.Shell
$shortcutPath = Join-Path $desktop "Helm.lnk"
$shortcut = $wsh.CreateShortcut($shortcutPath)

# Locate pythonw.exe or python.exe
$pythonCmd = Get-Command pythonw.exe -ErrorAction SilentlyContinue
if ($null -ne $pythonCmd) {
    $pythonExe = $pythonCmd.Source
} else {
    $pythonExe = (Get-Command python.exe).Source
}

$shortcut.TargetPath = $pythonExe
$shortcut.Arguments = "app.py"
$shortcut.WorkingDirectory = "D:\homie"
$shortcut.Description = "Launch Helm AI Workstation Assistant"

$iconPath = "D:\homie\ui\AppIcon.ico"
if (Test-Path $iconPath) {
    $shortcut.IconLocation = "$iconPath,0"
}

$shortcut.Save()
Write-Output "SUCCESS: Created $shortcutPath targeting $pythonExe"
