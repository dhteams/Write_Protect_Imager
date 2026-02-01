#!/usr/bin/env python3
"""
USB Write Blocker + Imager
Version 2.1.0 - Modular Architecture

Professional forensic tool for:
- USB write protection (registry-based)
- Forensic disk imaging (dd-based with MD5/SHA-1)

Requires Administrator privileges on Windows.
"""

import sys
import os
import logging
import ctypes

from PySide6 import QtCore, QtGui, QtWidgets

# Import from forensic_tools package
from forensic_tools import (
    APP_TITLE,
    APP_VERSION,
    IS_WINDOWS,
    USBWriteBlocker,
    ImagingDialog,
    E01ArchiveDialog,
    ImageVerificationDialog,
    WipeDialog,
    HelpDialog,
    QtLogHandler
)
from forensic_tools.utils import get_tool_search_debug_info


class MainWindow(QtWidgets.QMainWindow):
    """
    Main application window.
    Provides UI for write protection control and access to imaging/RAM capture dialogs.
    """
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE} {APP_VERSION}")
        self.resize(1100, 680)
        self.apply_modern_theme()
        
        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll_area.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setCentralWidget(scroll_area)
        
        central = QtWidgets.QWidget()
        scroll_area.setWidget(central)
        v = QtWidgets.QVBoxLayout(central)
        v.setSpacing(16)
        v.setContentsMargins(32, 32, 32, 32)
        
        # Header
        header = QtWidgets.QHBoxLayout()
        title_lbl = QtWidgets.QLabel(f"<b>{APP_TITLE}</b>")
        title_lbl.setStyleSheet("font-size: 22px; font-weight: 700; color: #e8e8e8;")
        header.addWidget(title_lbl)
        
        version_lbl = QtWidgets.QLabel(APP_VERSION)
        version_lbl.setStyleSheet("font-size: 13px; color: #7a8290; font-weight: 500;")
        header.addWidget(version_lbl)
        header.addStretch(1)
        
        # Help button
        self.btn_help = self.mk_btn("Help")
        self.btn_help.setMinimumHeight(36)
        self.btn_help.setMinimumWidth(100)
        self.btn_help.setMaximumWidth(120)
        self.btn_help.clicked.connect(self.show_help)
        header.addWidget(self.btn_help)
        
        header.addSpacing(12)
        
        # Admin button
        self.btn_admin = self.mk_btn("Relaunch as Administrator")
        self.btn_admin.setMinimumHeight(36)
        self.btn_admin.setMinimumWidth(200)
        self.btn_admin.setMaximumWidth(240)
        if self.is_admin():
            self.btn_admin.setEnabled(False)
            self.btn_admin.setText("Administrator Mode")
            self.btn_admin.setToolTip("Running with Administrator privileges")
        else:
            self.btn_admin.clicked.connect(self.relaunch_as_admin)
        
        header.addWidget(self.btn_admin)
        v.addLayout(header)
        
        # Divider
        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.HLine)
        line.setStyleSheet("background: #2d3139; max-height: 1px; margin: 8px 0px;")
        v.addWidget(line)
        
        v.addSpacing(12)
        
        # Status section
        status_row = QtWidgets.QHBoxLayout()
        status_label = QtWidgets.QLabel("Write Protection Status:")
        status_label.setStyleSheet("font-weight: 600; color: #c8ccd4; font-size: 13px;")
        status_row.addWidget(status_label)
        status_row.addSpacing(12)
        
        self.status_chip = QtWidgets.QLabel("DISABLED")
        self.status_chip.setObjectName("StatusChip")
        status_row.addWidget(self.status_chip)
        status_row.addStretch(1)
        
        # Wipe Device button (moved from section below)
        self.btn_wipe = self.mk_btn("Wipe Device")
        self.btn_wipe.setMinimumHeight(36)
        self.btn_wipe.setMinimumWidth(120)
        self.btn_wipe.setMaximumWidth(140)
        self.btn_wipe.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_wipe.clicked.connect(self.on_wipe_device)
        self.btn_wipe.setToolTip("Secure disk wipe (Experimental)")
        status_row.addWidget(self.btn_wipe)
        
        v.addLayout(status_row)
        
        v.addSpacing(8)
        
        # Write Block section
        write_block_group = QtWidgets.QGroupBox("Write Block")
        write_block_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
                font-size: 13px;
                color: #e8e8e8;
                border: 2px solid #2d3139;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 20px;
                padding-bottom: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
            }
        """)
        write_block_layout = QtWidgets.QVBoxLayout(write_block_group)
        write_block_layout.setSpacing(16)
        
        write_protection_row = QtWidgets.QHBoxLayout()
        write_protection_row.setSpacing(16)
        write_protection_row.addStretch(1)
        
        self.btn_enable = self.mk_btn("Enable Write Protection")
        self.btn_enable.setMinimumHeight(48)
        self.btn_enable.setMinimumWidth(200)
        self.btn_enable.setMaximumWidth(250)
        self.btn_enable.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_enable.clicked.connect(self.on_enable)
        write_protection_row.addWidget(self.btn_enable)
        
        self.btn_disable = self.mk_btn("Disable Write Protection")
        self.btn_disable.setMinimumHeight(48)
        self.btn_disable.setMinimumWidth(200)
        self.btn_disable.setMaximumWidth(250)
        self.btn_disable.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_disable.clicked.connect(self.on_disable)
        self.btn_disable.setEnabled(False)
        write_protection_row.addWidget(self.btn_disable)
        
        write_protection_row.addStretch(1)
        write_block_layout.addLayout(write_protection_row)
        
        v.addWidget(write_block_group)
        
        v.addSpacing(16)
        
        # Forensic Imaging section
        imaging_group = QtWidgets.QGroupBox("Forensic Imaging")
        imaging_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
                font-size: 13px;
                color: #e8e8e8;
                border: 2px solid #2d3139;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 20px;
                padding-bottom: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
            }
        """)
        imaging_layout = QtWidgets.QVBoxLayout(imaging_group)
        imaging_layout.setSpacing(16)
        
        image_row = QtWidgets.QHBoxLayout()
        image_row.addStretch(1)
        
        self.btn_image = self.mk_btn("Create Forensic Image")
        self.btn_image.setMinimumHeight(64)
        self.btn_image.setMinimumWidth(200)
        self.btn_image.setMaximumWidth(280)
        self.btn_image.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_image.clicked.connect(self.on_image_device)
        image_row.addWidget(self.btn_image)
        
        image_row.addStretch(1)
        imaging_layout.addLayout(image_row)
        
        v.addWidget(imaging_group)
        
        v.addSpacing(16)
        
        # Archiving section
        archiving_group = QtWidgets.QGroupBox("Archiving")
        archiving_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
                font-size: 13px;
                color: #e8e8e8;
                border: 2px solid #2d3139;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 20px;
                padding-bottom: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
            }
        """)
        archiving_layout = QtWidgets.QVBoxLayout(archiving_group)
        archiving_layout.setSpacing(16)
        
        # Verify and Archive buttons
        archive_row = QtWidgets.QHBoxLayout()
        archive_row.addStretch(1)
        
        self.btn_verify = self.mk_btn("Verify Image")
        self.btn_verify.setMinimumHeight(64)
        self.btn_verify.setMinimumWidth(200)
        self.btn_verify.setMaximumWidth(250)
        self.btn_verify.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_verify.clicked.connect(self.on_verify_image)
        archive_row.addWidget(self.btn_verify)
        
        archive_row.addSpacing(16)
        
        self.btn_archive = self.mk_btn("Archive Image (E01)")
        self.btn_archive.setMinimumHeight(64)
        self.btn_archive.setMinimumWidth(200)
        self.btn_archive.setMaximumWidth(250)
        self.btn_archive.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_archive.clicked.connect(self.on_archive_image)
        archive_row.addWidget(self.btn_archive)
        
        archive_row.addStretch(1)
        archiving_layout.addLayout(archive_row)
        
        v.addWidget(archiving_group)
        
        v.addSpacing(16)
        
        # Info note
        note = QtWidgets.QLabel(
            "- Administrator privileges required for all operations\n"
            "- Enable write protection before connecting evidence media\n"
            "- Verify Image checks hash integrity of existing images\n"
            "- Archive Image (Archiving section) converts raw .img/.dd files to E01 format"
        )
        note.setStyleSheet("""
            color: #7a8290;
            font-size: 12px;
            padding: 16px;
            background: #1e2129;
            border-radius: 8px;
            border: 1px solid #2d3139;
        """)
        v.addWidget(note)
        
        v.addStretch(1)
        
        # Activity Log
        log_group = QtWidgets.QGroupBox("Activity Log")
        log_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
                font-size: 13px;
                color: #e8e8e8;
                border: 2px solid #2d3139;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
            }
        """)
        log_layout = QtWidgets.QVBoxLayout(log_group)
        
        self.log_text = QtWidgets.QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(1000)
        self.log_text.setMinimumHeight(120)
        self.log_text.setStyleSheet("""
            QPlainTextEdit {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                color: #c8ccd4;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        log_layout.addWidget(self.log_text)
        
        # Export button
        log_btn_row = QtWidgets.QHBoxLayout()
        log_btn_row.addStretch()
        self.btn_export_log = self.mk_btn("Export Log")
        self.btn_export_log.setMinimumWidth(120)
        self.btn_export_log.clicked.connect(self.export_log)
        log_btn_row.addWidget(self.btn_export_log)
        log_layout.addLayout(log_btn_row)
        
        v.addWidget(log_group)
        
        # Initialize components
        self.blocker = USBWriteBlocker()
        
        # Setup logging
        self.logger = logging.getLogger("ForensicTools")
        self.logger.setLevel(logging.DEBUG)
        handler = QtLogHandler(self.log_text)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", datefmt="%H:%M:%S"))
        self.logger.addHandler(handler)
        
        # Initial status check
        self.refresh_status()
        self.logger.info(f"{APP_TITLE} {APP_VERSION} initialized")
        if self.is_admin():
            self.logger.info("Running with Administrator privileges")
        else:
            self.logger.warning("NOT running as Administrator - some features may not work")
        
        # Log tool search paths for debugging
        self.logger.info("=== Tool Path Debug Info ===")
        for line in get_tool_search_debug_info().split('\n'):
            self.logger.info(line)
    
    def apply_modern_theme(self):
        """Apply modern dark theme styling."""
        self.setStyleSheet("""
            QMainWindow {
                background: #1a1d23;
            }
            QLabel {
                color: #e8e8e8;
            }
            #StatusChip {
                background: #7f1d1d;
                color: #ff4444;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: 700;
                font-size: 14px;
                border: 2px solid #dc2626;
            }
        """)
    
    def mk_btn(self, text: str) -> QtWidgets.QPushButton:
        """Create a styled button."""
        btn = QtWidgets.QPushButton(text)
        btn.setStyleSheet("""
            QPushButton {
                background: #2d3440;
                color: #e8e8e8;
                border: 2px solid #3a4150;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 13px;
            }
            QPushButton:hover {
                background: #3a4150;
                border-color: #4a5162;
            }
            QPushButton:disabled {
                background: #1e2129;
                color: #5a6270;
                border-color: #2a2f3a;
            }
        """)
        
        return btn
    
    def is_admin(self) -> bool:
        """Check if running with Administrator privileges."""
        if not IS_WINDOWS:
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except:
            return False
    
    def require_admin(self) -> bool:
        """Check for admin privileges and show warning if not admin."""
        if not self.is_admin():
            QtWidgets.QMessageBox.warning(
                self, "Administrator Required",
                "This operation requires Administrator privileges.\n\n"
                "Please relaunch the application as Administrator."
            )
            return False
        return True
    
    def relaunch_as_admin(self):
        """Relaunch application with Administrator privileges."""
        if IS_WINDOWS:
            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                QtWidgets.QApplication.quit()
            except Exception:
                QtWidgets.QMessageBox.critical(
                    self, "Error",
                    "Failed to relaunch as Administrator.\n\n"
                    "Please manually run the application as Administrator."
                )
    
    def refresh_status(self):
        """Refresh write protection status display and button states."""
        if self.blocker.verify():
            self.status_chip.setText("ENABLED")
            self.status_chip.setStyleSheet("""
                background: #166534;
                color: #22ff22;
                border: 2px solid #22c55e;
                font-weight: 700;
                padding: 8px 20px;
                border-radius: 6px;
                font-size: 14px;
            """)
            self.blocker.registry_protected = True
            # Enable disable button, disable enable button
            self.btn_enable.setEnabled(False)
            self.btn_disable.setEnabled(True)
            if hasattr(self, 'logger'):
                self.logger.info("Status: Write protection is ENABLED")
        else:
            self.status_chip.setText("DISABLED")
            self.status_chip.setStyleSheet("""
                background: #7f1d1d;
                color: #ff4444;
                border: 2px solid #dc2626;
                font-weight: 700;
                padding: 8px 20px;
                border-radius: 6px;
                font-size: 14px;
            """)
            self.blocker.registry_protected = False
            # Enable enable button, disable disable button
            self.btn_enable.setEnabled(True)
            self.btn_disable.setEnabled(False)
            if hasattr(self, 'logger'):
                self.logger.info("Status: Write protection is DISABLED")
    
    def on_enable(self):
        """Enable write protection."""
        if not self.require_admin():
            return
        
        self.logger.info("=== Enable Write Protection ===")
        self.logger.info("Attempting to enable USB write protection...")
        
        if self.blocker.enable():
            self.refresh_status()
            self.logger.info("Write protection ENABLED successfully")
            QtWidgets.QMessageBox.information(
                self, "Success",
                "USB write protection has been enabled.\n\n"
                "All USB devices are now write-protected."
            )
        else:
            self.logger.error("Failed to enable write protection")
            QtWidgets.QMessageBox.critical(
                self, "Error",
                "Failed to enable write protection.\n\n"
                "Make sure you're running as Administrator."
            )
    
    def on_disable(self):
        """Disable write protection."""
        if not self.require_admin():
            return
        
        self.logger.info("=== Disable Write Protection ===")
        self.logger.info("Attempting to disable USB write protection...")
        
        if self.blocker.disable():
            self.refresh_status()
            self.logger.info("Write protection DISABLED successfully")
            QtWidgets.QMessageBox.information(
                self, "Success",
                "USB write protection has been disabled."
            )
        else:
            self.logger.error("Failed to disable write protection")
            QtWidgets.QMessageBox.critical(
                self, "Error",
                "Failed to disable write protection."
            )
    
    def on_image_device(self):
        """Open forensic imaging dialog."""
        if not self.require_admin():
            return
        
        self.logger.info("=" * 50)
        self.logger.info("=== FORENSIC IMAGING DIALOG ===")
        self.logger.info("=" * 50)
        dialog = ImagingDialog(self, self.blocker, self.logger)
        result = dialog.exec()
        if result == QtWidgets.QDialog.Accepted:
            self.logger.info("Forensic Imaging dialog closed")
        else:
            self.logger.info("Forensic Imaging dialog cancelled")
    
    def on_archive_image(self):
        """Open E01 archive conversion dialog."""
        self.logger.info("=" * 50)
        self.logger.info("=== E01 ARCHIVE DIALOG ===")
        self.logger.info("=" * 50)
        dialog = E01ArchiveDialog(self, self.logger)
        result = dialog.exec()
        if result == QtWidgets.QDialog.Accepted:
            self.logger.info("E01 Archive dialog closed")
        else:
            self.logger.info("E01 Archive dialog cancelled")
    
    def on_verify_image(self):
        """Open image verification dialog."""
        self.logger.info("=" * 50)
        self.logger.info("=== IMAGE VERIFICATION DIALOG ===")
        self.logger.info("=" * 50)
        dialog = ImageVerificationDialog(self, self.logger)
        result = dialog.exec()
        if result == QtWidgets.QDialog.Accepted:
            self.logger.info("Image Verification dialog closed")
        else:
            self.logger.info("Image Verification dialog cancelled")
    
    def on_wipe_device(self):
        """Open secure disk wipe dialog."""
        self.logger.info("=" * 50)
        self.logger.info("=== SECURE DISK WIPE DIALOG ===")
        self.logger.info("=" * 50)
        dialog = WipeDialog(self, self.blocker, self.logger)
        result = dialog.exec()
        if result == QtWidgets.QDialog.Accepted:
            self.logger.info("Secure Disk Wipe dialog closed")
        else:
            self.logger.info("Secure Disk Wipe dialog cancelled")
    
    def show_help(self):
        """Show help dialog."""
        dialog = HelpDialog(self)
        dialog.exec()
    
    def export_log(self):
        """Export activity log to a text file."""
        import datetime
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"Activity_Log_{timestamp}.txt"
        
        desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
        start_dir = desktop if os.path.isdir(desktop) else os.getcwd()
        
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export Activity Log",
            os.path.join(start_dir, default_name),
            "Text files (*.txt);;All files (*.*)"
        )
        
        if filepath:
            try:
                log_content = self.log_text.toPlainText()
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"USB Write Blocker + Imager - Activity Log\n")
                    f.write(f"Exported: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(log_content)
                
                QtWidgets.QMessageBox.information(
                    self, "Log Exported",
                    f"Activity log exported successfully to:\n{filepath}"
                )
                self.logger.info(f"Activity log exported to: {filepath}")
            except Exception as e:
                QtWidgets.QMessageBox.critical(
                    self, "Export Failed",
                    f"Failed to export log:\n{e}"
                )
                self.logger.error(f"Failed to export log: {e}")


def main():
    """Application entry point."""
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setApplicationVersion(APP_VERSION)
    
    # Set application icon if available
    try:
        app.setWindowIcon(QtGui.QIcon("usb_imager_icon.ico"))
    except:
        pass
    
    # Close PyInstaller splash screen if it exists
    try:
        import pyi_splash
        pyi_splash.close()
    except ImportError:
        pass  # Not running as PyInstaller bundle
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
