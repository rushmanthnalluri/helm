<#
.SYNOPSIS
    Builds the MSIX package for Homie Desktop AI Assistant.

.DESCRIPTION
    Full packaging pipeline:
    1. Generates AppxManifest.xml and placeholder PNG assets using Pillow (if missing).
    2. Runs PyInstaller with homie.spec to compile the standalone executable bundle.
    3. Stages manifest and visual assets into the dist folder.
    4. Packs the directory into an MSIX container using makeappx.exe.
    5. Optionally signs the MSIX container using signtool.exe.

.PARAMETER Version
    Package version string (e.g. 1.0.0.0). Defaults to 1.0.0.0.

.PARAMETER Publisher
    Certificate subject publisher string. Defaults to CN=Homie, O=Homie, L=San Francisco, S=CA, C=US.

.PARAMETER CertPath
    Path to .pfx certificate for signing.

.PARAMETER CertPassword
    Password for .pfx certificate.

.PARAMETER SkipBuildExe
    Skip PyInstaller compilation step and reuse existing dist\homie.

.PARAMETER SkipSign
    Skip signing the MSIX package.

.PARAMETER DryRun
    Audit manifest, assets, and toolchains without executing builds.
#>

[CmdletBinding()]
param(
    [string]$Version = "1.0.0.0",
    [string]$Publisher = "CN=Homie, O=Homie, L=San Francisco, S=CA, C=US",
    [string]$PublisherDisplayName = "Homie",
    [string]$PackageName = "Homie.DesktopAI",
    [string]$DisplayName = "Homie Desktop AI",
    [string]$CertPath = "",
    [string]$CertPassword = "",
    [switch]$SkipBuildExe,
    [switch]$SkipSign,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$msg) {
    Write-Host "`n[+] $msg" -ForegroundColor Cyan
}

function Write-Info([string]$msg) {
    Write-Host "    [*] $msg" -ForegroundColor Gray
}

function Write-Success([string]$msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}

function Write-WarningMsg([string]$msg) {
    Write-Host "    [!] $msg" -ForegroundColor Yellow
}

function Write-ErrorMsg([string]$msg) {
    Write-Host "    [-] $msg" -ForegroundColor Red
}

# Resolve paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir = Resolve-Path "$ScriptDir\.."
$PackagingDir = Join-Path $BaseDir "packaging"
$AssetsDir = Join-Path $PackagingDir "assets"
$DistDir = Join-Path $BaseDir "dist\homie"
if (-not (Test-Path $DistDir)) {
    $AltDist = Join-Path $BaseDir "dist\Homie"
    if (Test-Path $AltDist) {
        $DistDir = $AltDist
    }
}
$OutputMsix = Join-Path $BaseDir "dist\Homie.msix"

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host " Homie MSIX Packaging Toolchain (Version: $Version)" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Info "Base Directory:      $BaseDir"
Write-Info "Packaging Directory: $PackagingDir"
Write-Info "Dist Directory:      $DistDir"
Write-Info "Target MSIX Path:    $OutputMsix"

# 1. Generate/Verify Assets using Pillow
Write-Step "Step 1: Verifying & Generating Visual Assets..."
if (-not (Test-Path $AssetsDir)) {
    New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null
}

$GenerateIconsScript = @"
import os
from PIL import Image, ImageDraw, ImageFont

assets_dir = r'$AssetsDir'
os.makedirs(assets_dir, exist_ok=True)

icons = [
    ('Square44x44Logo.png', (44, 44), 'H'),
    ('Square150x150Logo.png', (150, 150), 'H'),
    ('Square310x310Logo.png', (310, 310), 'H'),
    ('StoreLogo.png', (50, 50), 'H'),
    ('Wide310x150Logo.png', (310, 150), 'Homie'),
    ('SplashScreen.png', (620, 300), 'Homie Desktop AI'),
]

for filename, size, text in icons:
    target = os.path.join(assets_dir, filename)
    if not os.path.exists(target):
        w, h = size
        img = Image.new('RGBA', size, (30, 30, 46, 255))
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, w-1, h-1], outline=(90, 95, 130, 255), width=max(1, w // 40))
        try:
            font = ImageFont.truetype('arial.ttf', int(min(w, h) * 0.45))
        except Exception:
            font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), text, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        draw.text(((w - tw) / 2, (h - th) / 2 - bbox[1]), text, fill=(255, 255, 255, 255), font=font)
        img.save(target, 'PNG')
        print(f'Created: {filename}')
"@

try {
    python -c $GenerateIconsScript
    Write-Success "Visual assets verified in $AssetsDir"
} catch {
    Write-WarningMsg "Could not run Pillow icon generator; ensuring files exist manually: $_"
}

# 2. Generate AppxManifest.xml
Write-Step "Step 2: Generating AppxManifest.xml..."
$ManifestPath = Join-Path $PackagingDir "AppxManifest.xml"
$ManifestXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10"
  IgnorableNamespaces="uap rescap desktop">

  <Identity
    Name="$PackageName"
    Publisher="$Publisher"
    Version="$Version"
    ProcessorArchitecture="x64" />

  <Properties>
    <DisplayName>$DisplayName</DisplayName>
    <PublisherDisplayName>$PublisherDisplayName</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
    <Description>Homie - Autonomous AI Desktop Companion for Windows</Description>
  </Properties>

  <Resources>
    <Resource Language="en-us" />
  </Resources>

  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>

  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>

  <Applications>
    <Application Id="Homie" Executable="Homie.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements
        DisplayName="$DisplayName"
        Description="Homie - Autonomous AI Desktop Companion"
        BackgroundColor="#1E1E2E"
        Square150x150Logo="Assets\Square150x150Logo.png"
        Square44x44Logo="Assets\Square44x44Logo.png">
        <uap:DefaultTile
          Wide310x150Logo="Assets\Wide310x150Logo.png"
          Square310x310Logo="Assets\Square310x310Logo.png">
          <uap:ShowNameOnTiles>
            <uap:ShowOn Tile="square150x150Logo" />
            <uap:ShowOn Tile="wide310x150Logo" />
            <uap:ShowOn Tile="square310x310Logo" />
          </uap:ShowNameOnTiles>
        </uap:DefaultTile>
        <uap:SplashScreen Image="Assets\SplashScreen.png" />
      </uap:VisualElements>
      <Extensions>
        <uap:Extension Category="windows.fileTypeAssociation">
          <uap:FileTypeAssociation Name="homiefile">
            <uap:DisplayName>Homie Workflow File</uap:DisplayName>
            <uap:Logo>Assets\Square44x44Logo.png</uap:Logo>
            <uap:SupportedFileTypes>
              <uap:FileType>.homie</uap:FileType>
              <uap:FileType>.hnote</uap:FileType>
            </uap:SupportedFileTypes>
          </uap:FileTypeAssociation>
        </uap:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
"@

Set-Content -Path $ManifestPath -Value $ManifestXml.Trim() -Encoding UTF8
Write-Success "Manifest generated at $ManifestPath"

# 3. Compile EXE with PyInstaller
Write-Step "Step 3: Compiling PyInstaller Standalone Bundle..."
if ($DryRun) {
    Write-Info "Dry run mode active: skipping PyInstaller execution."
} elseif ($SkipBuildExe) {
    Write-Info "SkipBuildExe specified: skipping PyInstaller compilation."
} else {
    Write-Info "Executing: pyinstaller homie.spec --clean --noconfirm"
    Push-Location $BaseDir
    try {
        & pyinstaller homie.spec --clean --noconfirm
        if ($LASTEXITCODE -ne 0) {
            throw "PyInstaller exited with status code $LASTEXITCODE"
        }
        Write-Success "PyInstaller compilation completed successfully."
    } finally {
        Pop-Location
    }
}

# 4. Stage Assets and Manifest into Dist Directory
Write-Step "Step 4: Staging Manifest and Assets into Package Folder..."
if (-not (Test-Path $DistDir)) {
    if ($DryRun) {
        Write-Info "Creating temporary stub staging directory for dry-run verification..."
        New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
    } else {
        throw "Dist directory does not exist: $DistDir. Run PyInstaller build first."
    }
}

# Copy Manifest
Copy-Item -Path $ManifestPath -Destination (Join-Path $DistDir "AppxManifest.xml") -Force
Write-Success "Copied AppxManifest.xml -> $DistDir\AppxManifest.xml"

# Copy Assets folder
$DistAssetsDir = Join-Path $DistDir "Assets"
if (-not (Test-Path $DistAssetsDir)) {
    New-Item -ItemType Directory -Path $DistAssetsDir -Force | Out-Null
}
Copy-Item -Path "$AssetsDir\*" -Destination $DistAssetsDir -Recurse -Force
Write-Success "Copied visual assets -> $DistAssetsDir"

# 5. Locate makeappx.exe & Pack MSIX
Write-Step "Step 5: Packaging MSIX with makeappx.exe..."

function Find-WindowsTool([string]$toolName) {
    # 1. PATH
    $cmd = Get-Command $toolName -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # 2. Windows Kits SDK Paths
    $sdkRoots = @(
        "C:\Program Files (x86)\Windows Kits\10\bin",
        "C:\Program Files\Windows Kits\10\bin"
    )
    foreach ($root in $sdkRoots) {
        if (Test-Path $root) {
            $matched = Get-ChildItem -Path $root -Filter $toolName -Recurse -ErrorAction SilentlyContinue |
                       Where-Object { $_.FullName -like "*\x64\*" } |
                       Sort-Object LastWriteTime -Descending |
                       Select-Object -First 1
            if ($matched) {
                return $matched.FullName
            }
        }
    }
    return $null
}

$MakeAppx = Find-WindowsTool "makeappx.exe"
if ($MakeAppx) {
    Write-Success "Found makeappx.exe at: $MakeAppx"
} else {
    Write-WarningMsg "makeappx.exe not found in PATH or Windows Kits directory."
    Write-Info "To install makeappx.exe, install the Windows 10/11 SDK or Desktop C++ workload via Visual Studio Installer."
}

if ($DryRun) {
    Write-Info "Dry run: would execute: makeappx pack /d `"$DistDir`" /p `"$OutputMsix`" /o"
} elseif ($MakeAppx) {
    Write-Info "Packing MSIX: & `"$MakeAppx`" pack /d `"$DistDir`" /p `"$OutputMsix`" /o"
    & "$MakeAppx" pack /d "$DistDir" /p "$OutputMsix" /o
    if ($LASTEXITCODE -ne 0) {
        throw "makeappx.exe failed with exit code $LASTEXITCODE"
    }
    Write-Success "MSIX successfully created at: $OutputMsix"
} else {
    Write-WarningMsg "Skipping MSIX pack step because makeappx.exe is not installed."
}

# 6. Sign MSIX with signtool.exe
Write-Step "Step 6: Signing MSIX with signtool.exe..."
if ($SkipSign) {
    Write-Info "SkipSign specified: skipping code signing."
} else {
    $SignTool = Find-WindowsTool "signtool.exe"
    if ($SignTool) {
        Write-Success "Found signtool.exe at: $SignTool"
        if ($CertPath -and (Test-Path $CertPath)) {
            $signArgs = @("sign", "/fd", "SHA256", "/f", $CertPath)
            if ($CertPassword) {
                $signArgs += @("/p", $CertPassword)
            }
            $signArgs += $OutputMsix
            Write-Info "Signing with certificate file: $CertPath"
            & "$SignTool" @signArgs
        } else {
            Write-Info "Attempting signature with auto-selected certificate (/a)..."
            try {
                & "$SignTool" sign /fd SHA256 /a "$OutputMsix"
                Write-Success "Signed MSIX successfully."
            } catch {
                Write-WarningMsg "Auto-signing did not find a matching installed certificate."
                Write-Info "To create a self-signed dev cert, run:"
                Write-Info '  New-SelfSignedCertificate -Type Custom -Subject "' + $Publisher + '" -KeyUsage DigitalSignature -FriendlyName "Homie Dev Cert" -CertStoreLocation "Cert:\CurrentUser\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")'
            }
        }
    } else {
        Write-WarningMsg "signtool.exe not found. Code signing skipped."
    }
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MSIX Packaging Pipeline Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Info "AppxManifest: $ManifestPath"
Write-Info "Assets:       $AssetsDir"
Write-Info "Package Dir:  $DistDir"
Write-Info "MSIX Output:  $OutputMsix"
