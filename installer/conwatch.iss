; Inno Setup script. Build: iscc installer\conwatch.iss  (expects target\release\ built first)
#define AppVersion "0.1.0"

[Setup]
AppName=ConWatch
AppVersion={#AppVersion}
AppPublisher=ConWatch contributors
AppId={{6C1F2B7A-3E54-4B0E-9B5A-0C0A5D3E7F01}
DefaultDirName={autopf}\ConWatch
DefaultGroupName=ConWatch
OutputDir=..\dist
OutputBaseFilename=conwatch-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
LicenseFile=..\LICENSE
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\conwatch-app.exe

[Files]
Source: "..\target\release\conwatch-app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\conwatch.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\modules\*"; DestDir: "{app}\modules"; Flags: ignoreversion recursesubdirs
Source: "..\sdk\*"; DestDir: "{app}\sdk"; Excludes: "__pycache__"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\ConWatch"; Filename: "{app}\conwatch-app.exe"
Name: "{commondesktop}\ConWatch"; Filename: "{app}\conwatch-app.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"
Name: "autostart"; Description: "Start ConWatch when I sign in"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ConWatch"; ValueData: """{app}\conwatch-app.exe"""; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\conwatch-app.exe"; Description: "Launch ConWatch"; Flags: nowait postinstall skipifsilent
