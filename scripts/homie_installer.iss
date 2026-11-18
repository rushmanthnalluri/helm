; scripts/homie_installer.iss - Production Inno Setup Installer for Homie
; Compiles a single-binary Windows installer (.exe) for Homie Desktop Assistant.
;
; Supports:
; 1. Standalone binary packaging (dist\Homie\Homie.exe) with source-tree fallback (run.bat).
; 2. Dual-scope installation: user-level (AppData\Local\Programs) or machine-wide (Program Files).
; 3. Automatic Start Menu and Desktop shortcuts with custom AppIcon.
; 4. System startup tray launcher task.
; 5. homie:// custom URI protocol scheme registration.
; 6. Windows App Paths registration for cmd / Win+R execution.
; 7. Silent and unattended deployments via /VERYSILENT /SUPPRESSMSGBOXES.
; 8. Clean, automated uninstallation removing runtime caches and registry entries.

#define MyAppName "Homie"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Homie AI"
#define MyAppURL "https://github.com/homie-ai/homie"
#define MyAppExeName "Homie.exe"
#define MyAppFallbackBat "run.bat"
#define MyAppId "{{A14B87C2-E682-4E67-9FA0-377E2A91F601}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=Homie-Setup-{#MyAppVersion}
SetupIconFile=..\ui\AppIcon.ico
UninstallDisplayIcon={app}\ui\AppIcon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=yes
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Desktop AI Assistant Installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Launch Homie minimized in system tray when logging into Windows"; GroupDescription: "Windows Integration:"

[Files]
; Standalone PyInstaller onedir distribution (when pre-compiled)
Source: "..\dist\Homie\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: HasStandaloneBuild

; Portable source fallback distribution (when standalone binary is not pre-compiled)
Source: "..\app.py"; DestDir: "{app}"; Flags: ignoreversion; Check: not HasStandaloneBuild
Source: "..\homie.py"; DestDir: "{app}"; Flags: ignoreversion; Check: not HasStandaloneBuild
Source: "..\run.bat"; DestDir: "{app}"; Flags: ignoreversion; Check: not HasStandaloneBuild
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion; Check: not HasStandaloneBuild
Source: "..\*.py"; DestDir: "{app}"; Flags: ignoreversion; Excludes: "tests\*,scripts\*"; Check: not HasStandaloneBuild
Source: "..\ui\*"; DestDir: "{app}\ui"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: DirExists(ExpandConstant('{#SourcePath}\..\config'))

[Icons]
; Start Menu Shortcut
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Check: HasStandaloneBuild; IconFilename: "{app}\ui\AppIcon.ico"
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppFallbackBat}"; Check: not HasStandaloneBuild; IconFilename: "{app}\ui\AppIcon.ico"

; Desktop Shortcut
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; Check: HasStandaloneBuild; IconFilename: "{app}\ui\AppIcon.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppFallbackBat}"; Tasks: desktopicon; Check: not HasStandaloneBuild; IconFilename: "{app}\ui\AppIcon.ico"

; Startup Shortcut (System Tray Mode)
Name: "{autostartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--tray"; Tasks: startupicon; Check: HasStandaloneBuild; IconFilename: "{app}\ui\AppIcon.ico"
Name: "{autostartup}\{#MyAppName}"; Filename: "{app}\{#MyAppFallbackBat}"; Parameters: "--tray"; Tasks: startupicon; Check: not HasStandaloneBuild; IconFilename: "{app}\ui\AppIcon.ico"

[Registry]
; 1. Custom Protocol Registration: homie://
Root: HKA; Subkey: "Software\Classes\homie"; ValueType: string; ValueName: ""; ValueData: "URL:Homie Protocol"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\homie"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\homie\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\ui\AppIcon.ico,0"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\homie\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Check: HasStandaloneBuild; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\homie\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppFallbackBat}"" ""%1"""; Check: not HasStandaloneBuild; Flags: uninsdeletekey

; 2. Windows Run Dialog & CLI App Paths Registration (Allows Win+R -> 'homie')
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName}"; Check: HasStandaloneBuild; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; ValueType: string; ValueName: "Path"; ValueData: "{app}"; Check: HasStandaloneBuild; Flags: uninsdeletekey

; 3. Application Metadata
Root: HKA; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent; Check: HasStandaloneBuild
Filename: "{app}\{#MyAppFallbackBat}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: shellexec nowait postinstall skipifsilent; Check: not HasStandaloneBuild

[UninstallDelete]
Type: filesandordirs; Name: "{app}\.homie_staging"
Type: filesandordirs; Name: "{app}\__pycache__"
Type: files; Name: "{app}\*.log"

[Code]
function HasStandaloneBuild(): Boolean;
begin
  Result := FileExists(ExpandConstant('{#SourcePath}\..\dist\Homie\Homie.exe'));
end;
