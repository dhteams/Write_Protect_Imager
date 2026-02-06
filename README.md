# USB Write Blocker + Forensic Imager

Professional forensic imaging tool for Windows 10/11.

## Features

- USB Write Protection (registry-based)
- Forensic Disk Imaging with hash verification
- E01 Archive conversion
- Image Verification
- Secure Disk Wipe

## Requirements

- Windows 10/11 (x64)
- Administrator privileges
- Python 3.10+ (for compilation)

## Compilation

### Step 1: Install Python Dependencies

```
pip install PySide6 pyinstaller
```

### Step 2: Build Executable with PyInstaller

```
pyinstaller USB_Write_Blocker_Imager.spec
```

This creates the executable in the `dist\USB_Write_Blocker_Imager\` folder.

### Step 3: Create Installer (Optional)

1. Download and install [Inno Setup](https://jrsoftware.org/isinfo.php)
2. Open `USB_Write_Blocker_Installer.iss` in Inno Setup
3. Click **Build > Compile** (or press F9)
4. Installer will be created in the `Output\` folder

## Folder Structure

```
Write_Protect_Imager/
├── forensic_tools/          # Python modules
├── tsk_bin/                  # External tools (dd.exe, ewfacquire.exe)
├── splash.png                # Splash screen image
├── usb_imager_icon.ico       # Application icon
├── usb_write_blocker_imager.py   # Main application
├── USB_Write_Blocker_Imager.spec # PyInstaller spec file
└── USB_Write_Blocker_Installer.iss # Inno Setup script
```

## External Tools

Place these in the `tsk_bin\` folder:

- `dd.exe` - GNU dd for Windows (disk imaging)
- `ewfacquire.exe` - libewf (E01 conversion)

## License

MIT / GPL-3.0
