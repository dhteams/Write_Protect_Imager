; USB Write Blocker + Imager Installer
; v1.8.1
;
; Build command:
; pyinstaller --clean -y --onefile --uac-admin --noconsole --name USB_Write_Blocker_Imager --icon usb_imager_icon.ico --collect-all PySide6 usb_write_blocker_gui_final.py

[Setup]
AppName=USB Write Blocker + Imager
AppVersion=2.0.0
AppPublisher=Forensic Tools
DefaultDirName={autopf}\USB Write Blocker Imager
DefaultGroupName=USB Write Blocker + Imager
OutputDir=installer_output
OutputBaseFilename=USB_Write_Blocker_Imager_Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\USB_Write_Blocker_Imager.exe
WizardStyle=modern
SetupIconFile=usb_imager_icon.ico

[Files]
Source: "dist\USB_Write_Blocker_Imager.exe"; DestDir: "{app}"; Flags: ignoreversion
; Note: If using --onedir instead of --onefile, use the line below:
; Source: "dist\USB_Write_Blocker_Imager\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Desktop and Start Menu shortcuts will automatically use the icon embedded in the .exe
Name: "{autoprograms}\USB Write Blocker + Imager"; Filename: "{app}\USB_Write_Blocker_Imager.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\USB Write Blocker + Imager"; Filename: "{app}\USB_Write_Blocker_Imager.exe"; WorkingDir: "{app}"

[Run]
Filename: "{app}\USB_Write_Blocker_Imager.exe"; Description: "Launch USB Write Blocker + Imager"; Flags: nowait postinstall skipifsilent shellexec
