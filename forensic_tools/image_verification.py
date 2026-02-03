"""
Image Verification Module
Hash verification and integrity checking for forensic images
Supports both raw images (.img/.dd/.raw) and E01 archives using pyewf
"""

import os
import hashlib
import logging
import time
from pathlib import Path
from PySide6 import QtCore, QtWidgets, QtGui

from .utils import APP_TITLE

# Check for pyewf (E01 support)
try:
    import pyewf
    HAS_PYEWF = True
except ImportError:
    HAS_PYEWF = False


class VerificationWorker(QtCore.QThread):
    """
    Worker thread for image hash verification.
    Calculates MD5, SHA-1, and optionally SHA-256 hashes.
    Supports E01 logical content hashing via pyewf.
    """
    progress = QtCore.Signal(int, str, str)
    finished = QtCore.Signal(dict)
    
    def __init__(self, filepath: str, calculate_sha256: bool = False):
        super().__init__()
        self.filepath = filepath
        self.calculate_sha256 = calculate_sha256
        self.should_cancel = False
    
    def cancel(self):
        """Request cancellation of the verification operation."""
        self.should_cancel = True
    
    def _get_adaptive_chunk_size(self, file_size: int) -> int:
        """Determine optimal chunk size based on file size."""
        if file_size < 100 * 1024 * 1024:  # < 100MB
            return 1024 * 1024  # 1MB
        elif file_size < 1024 * 1024 * 1024:  # < 1GB
            return 8 * 1024 * 1024  # 8MB
        elif file_size < 10 * 1024 * 1024 * 1024:  # < 10GB
            return 32 * 1024 * 1024  # 32MB
        else:
            return 64 * 1024 * 1024  # 64MB for huge files
    
    def run(self):
        """Calculate hashes for the image file."""
        try:
            file_path = Path(self.filepath)
            file_ext = file_path.suffix.lower()
            
            # Check if E01 file
            is_e01 = file_ext in ['.e01', '.ex01', '.ewf', '.s01']
            
            if is_e01:
                if HAS_PYEWF:
                    self._hash_e01_content()
                else:
                    # Fallback: hash container (will NOT match source hash)
                    self._hash_regular_file()
            else:
                self._hash_regular_file()
                
        except Exception as e:
            self.finished.emit({
                'error': str(e),
                'md5': None,
                'sha1': None,
                'sha256': None,
                'size': 0,
                'is_e01': False
            })
    
    def _hash_regular_file(self):
        """Hash a regular file (dd, img, raw)."""
        try:
            file_size = os.path.getsize(self.filepath)
            chunk_size = self._get_adaptive_chunk_size(file_size)
            
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256() if self.calculate_sha256 else None
            
            bytes_read = 0
            start_time = time.time()
            last_update = start_time
            
            with open(self.filepath, 'rb') as f:
                while True:
                    if self.should_cancel:
                        self.finished.emit({
                            'error': 'Verification cancelled by user',
                            'md5': None,
                            'sha1': None,
                            'sha256': None,
                            'size': file_size,
                            'is_e01': False
                        })
                        return
                    
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    if sha256_hash:
                        sha256_hash.update(chunk)
                    
                    bytes_read += len(chunk)
                    
                    current_time = time.time()
                    if current_time - last_update >= 0.5:
                        percent = int((bytes_read / file_size) * 100)
                        elapsed = max(0.01, current_time - start_time)
                        speed_mbps = (bytes_read / 1048576.0) / elapsed
                        
                        status = f"Processing: {bytes_read:,} / {file_size:,} bytes"
                        speed_str = f"{speed_mbps:.1f} MB/s"
                        
                        self.progress.emit(percent, status, speed_str)
                        last_update = current_time
            
            elapsed_total = time.time() - start_time
            
            self.progress.emit(100, "Hash calculation complete", "")
            self.finished.emit({
                'md5': md5_hash.hexdigest(),
                'sha1': sha1_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest() if sha256_hash else None,
                'size': file_size,
                'elapsed': elapsed_total,
                'error': None,
                'is_e01': False
            })
            
        except Exception as e:
            self.finished.emit({
                'error': str(e),
                'md5': None,
                'sha1': None,
                'sha256': None,
                'size': 0,
                'is_e01': False
            })
    
    def _hash_e01_content(self):
        """Hash logical content of E01 file using pyewf."""
        try:
            # Normalize path for Windows
            file_path_normalized = str(Path(self.filepath).resolve())
            filenames = pyewf.glob(file_path_normalized)
            
            if not filenames:
                filenames = [file_path_normalized]
            
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            
            media_size = ewf_handle.get_media_size()
            chunk_size = self._get_adaptive_chunk_size(media_size)
            
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256() if self.calculate_sha256 else None
            
            offset = 0
            start_time = time.time()
            last_update = start_time
            
            while offset < media_size:
                if self.should_cancel:
                    ewf_handle.close()
                    self.finished.emit({
                        'error': 'Verification cancelled by user',
                        'md5': None,
                        'sha1': None,
                        'sha256': None,
                        'size': media_size,
                        'is_e01': True
                    })
                    return
                
                bytes_to_read = min(chunk_size, media_size - offset)
                ewf_handle.seek(offset)
                chunk = ewf_handle.read(bytes_to_read)
                
                if not chunk:
                    break
                
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                if sha256_hash:
                    sha256_hash.update(chunk)
                
                offset += len(chunk)
                
                # Update progress
                current_time = time.time()
                if current_time - last_update >= 0.3:
                    percent = int((offset / media_size) * 100)
                    elapsed = max(0.01, current_time - start_time)
                    speed_mbps = (offset / (1024 * 1024)) / elapsed
                    
                    status = f"Processing E01: {offset:,} / {media_size:,} bytes"
                    speed_str = f"{speed_mbps:.1f} MB/s"
                    
                    self.progress.emit(percent, status, speed_str)
                    last_update = current_time
            
            ewf_handle.close()
            
            elapsed_total = time.time() - start_time
            
            self.progress.emit(100, "E01 hash calculation complete", "")
            self.finished.emit({
                'md5': md5_hash.hexdigest(),
                'sha1': sha1_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest() if sha256_hash else None,
                'size': media_size,
                'elapsed': elapsed_total,
                'is_e01': True,
                'error': None
            })
            
        except Exception as e:
            self.finished.emit({
                'error': f"E01 hashing failed: {str(e)}",
                'md5': None,
                'sha1': None,
                'sha256': None,
                'size': 0,
                'is_e01': True
            })


class ImageVerificationDialog(QtWidgets.QDialog):
    """
    Dialog for verifying forensic image integrity by recalculating hashes.
    Supports both raw images and E01 archives.
    Compares calculated hashes against expected values (manual entry or report file).
    """
    
    def __init__(self, parent: QtWidgets.QWidget, logger: logging.Logger):
        super().__init__(parent)
        self.logger = logger
        self.worker = None
        self.calculated_hashes = {}  # Store for copy buttons
        
        self.setWindowTitle(f"{APP_TITLE} - Image Verification")
        self.setModal(True)
        self.resize(1100, 750)
        self.setMinimumSize(900, 650)
        
        # Enable maximize button
        self.setWindowFlags(
            self.windowFlags() | 
            QtCore.Qt.WindowMaximizeButtonHint
        )
        
        self.apply_dark_theme()
        
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll_area.setFrameShape(QtWidgets.QFrame.NoFrame)
        main_layout.addWidget(scroll_area)
        
        content_widget = QtWidgets.QWidget()
        scroll_area.setWidget(content_widget)
        
        layout = QtWidgets.QVBoxLayout(content_widget)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 20, 24, 20)
        
        title = QtWidgets.QLabel("<b>Verify Forensic Image Integrity</b>")
        title.setStyleSheet("font-size: 18px; color: #e8e8e8;")
        layout.addWidget(title)
        
        subtitle = QtWidgets.QLabel(
            "Recalculate hashes for raw images (.img/.dd/.raw) or E01 archives and compare against expected values"
        )
        subtitle.setStyleSheet("color: #e8e8e8;")
        layout.addWidget(subtitle)
        
        # Show pyewf status
        if not HAS_PYEWF:
            warning = QtWidgets.QLabel(
                "⚠ pyewf not installed - E01 hashes will NOT match source image!\n"
                "Install with: pip install libewf-python"
            )
            warning.setStyleSheet("color: #ff6b6b; font-weight: bold; padding: 8px; background: #2a1a1a; border-radius: 4px;")
            layout.addWidget(warning)
        
        file_group = QtWidgets.QGroupBox("Image File")
        file_group.setStyleSheet(self.get_group_style())
        file_layout = QtWidgets.QVBoxLayout(file_group)
        
        file_row = QtWidgets.QHBoxLayout()
        self.file_input = QtWidgets.QLineEdit()
        self.file_input.setPlaceholderText("Select image file to verify (.img, .dd, .raw, .E01)")
        self.file_input.setStyleSheet(self.get_input_style())
        file_row.addWidget(self.file_input)
        
        btn_browse = QtWidgets.QPushButton("Browse...")
        btn_browse.setStyleSheet(self.get_button_style())
        btn_browse.clicked.connect(self.browse_image)
        file_row.addWidget(btn_browse)
        file_layout.addLayout(file_row)
        
        layout.addWidget(file_group)
        
        options_group = QtWidgets.QGroupBox("Hash Options")
        options_group.setStyleSheet(self.get_group_style())
        options_layout = QtWidgets.QVBoxLayout(options_group)
        
        self.sha256_check = QtWidgets.QCheckBox("Calculate SHA-256 (slower but more secure)")
        self.sha256_check.setStyleSheet("color: #e8e8e8;")
        self.sha256_check.setChecked(False)
        options_layout.addWidget(self.sha256_check)
        
        if HAS_PYEWF:
            note_label = QtWidgets.QLabel(
                "Note: E01 files will be hashed using logical content (matches FTK Imager)"
            )
        else:
            note_label = QtWidgets.QLabel(
                "Note: E01 files will be hashed as containers (will NOT match FTK Imager)"
            )
        note_label.setStyleSheet("color: #999; font-size: 11px; font-style: italic;")
        options_layout.addWidget(note_label)
        
        layout.addWidget(options_group)
        
        expected_group = QtWidgets.QGroupBox("Expected Hash Values (Optional)")
        expected_group.setStyleSheet(self.get_group_style())
        expected_layout = QtWidgets.QGridLayout(expected_group)
        expected_layout.setSpacing(12)
        
        expected_layout.addWidget(QtWidgets.QLabel("MD5:"), 0, 0)
        self.expected_md5 = QtWidgets.QLineEdit()
        self.expected_md5.setPlaceholderText("Enter expected MD5 hash (optional)")
        self.expected_md5.setStyleSheet(self.get_input_style())
        self.expected_md5.setMinimumWidth(500)
        expected_layout.addWidget(self.expected_md5, 0, 1)
        
        expected_layout.addWidget(QtWidgets.QLabel("SHA-1:"), 1, 0)
        self.expected_sha1 = QtWidgets.QLineEdit()
        self.expected_sha1.setPlaceholderText("Enter expected SHA-1 hash (optional)")
        self.expected_sha1.setStyleSheet(self.get_input_style())
        self.expected_sha1.setMinimumWidth(500)
        expected_layout.addWidget(self.expected_sha1, 1, 1)
        
        expected_layout.addWidget(QtWidgets.QLabel("SHA-256:"), 2, 0)
        self.expected_sha256 = QtWidgets.QLineEdit()
        self.expected_sha256.setPlaceholderText("Enter expected SHA-256 hash (optional)")
        self.expected_sha256.setStyleSheet(self.get_input_style())
        self.expected_sha256.setMinimumWidth(500)
        expected_layout.addWidget(self.expected_sha256, 2, 1)
        
        btn_load = QtWidgets.QPushButton("Load from Report File...")
        btn_load.setStyleSheet(self.get_button_style())
        btn_load.clicked.connect(self.load_from_report)
        expected_layout.addWidget(btn_load, 3, 0, 1, 2)
        
        layout.addWidget(expected_group)
        
        progress_group = QtWidgets.QGroupBox("Verification Progress")
        progress_group.setStyleSheet(self.get_group_style())
        progress_layout = QtWidgets.QVBoxLayout(progress_group)
        
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setStyleSheet(self.get_progress_style())
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QtWidgets.QLabel("Ready to verify")
        self.status_label.setStyleSheet("color: #e8e8e8;")
        progress_layout.addWidget(self.status_label)
        
        self.speed_label = QtWidgets.QLabel("")
        self.speed_label.setStyleSheet("color: #999; font-size: 11px;")
        progress_layout.addWidget(self.speed_label)
        
        layout.addWidget(progress_group)
        
        results_group = QtWidgets.QGroupBox("Verification Results")
        results_group.setStyleSheet(self.get_group_style())
        results_layout = QtWidgets.QVBoxLayout(results_group)
        
        self.results_text = QtWidgets.QPlainTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            QPlainTextEdit {
                background: #1e1e1e;
                border: 2px solid #3a3a3a;
                border-radius: 6px;
                padding: 12px;
                color: #e8e8e8;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        self.results_text.setMinimumHeight(200)
        results_layout.addWidget(self.results_text)
        
        # Copy buttons row
        copy_row = QtWidgets.QHBoxLayout()
        
        self.btn_copy_md5 = QtWidgets.QPushButton("Copy MD5")
        self.btn_copy_md5.setStyleSheet(self.get_button_style())
        self.btn_copy_md5.setEnabled(False)
        self.btn_copy_md5.clicked.connect(lambda: self.copy_hash('md5'))
        copy_row.addWidget(self.btn_copy_md5)
        
        self.btn_copy_sha1 = QtWidgets.QPushButton("Copy SHA-1")
        self.btn_copy_sha1.setStyleSheet(self.get_button_style())
        self.btn_copy_sha1.setEnabled(False)
        self.btn_copy_sha1.clicked.connect(lambda: self.copy_hash('sha1'))
        copy_row.addWidget(self.btn_copy_sha1)
        
        self.btn_copy_sha256 = QtWidgets.QPushButton("Copy SHA-256")
        self.btn_copy_sha256.setStyleSheet(self.get_button_style())
        self.btn_copy_sha256.setEnabled(False)
        self.btn_copy_sha256.clicked.connect(lambda: self.copy_hash('sha256'))
        copy_row.addWidget(self.btn_copy_sha256)
        
        self.btn_copy_all = QtWidgets.QPushButton("Copy All")
        self.btn_copy_all.setStyleSheet(self.get_button_style("#4a9eff"))  # Blue for "Copy All"
        self.btn_copy_all.setEnabled(False)
        self.btn_copy_all.clicked.connect(self.copy_all_hashes)
        copy_row.addWidget(self.btn_copy_all)
        
        copy_row.addStretch()
        results_layout.addLayout(copy_row)
        
        layout.addWidget(results_group)
        
        layout.addStretch()
        
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.setSpacing(12)
        
        self.btn_verify = QtWidgets.QPushButton("Start Verification")
        self.btn_verify.setStyleSheet(self.get_button_style("#28a745"))  # Green
        self.btn_verify.setMinimumHeight(40)
        self.btn_verify.clicked.connect(self.start_verification)
        button_layout.addWidget(self.btn_verify)
        
        self.btn_cancel = QtWidgets.QPushButton("Cancel")
        self.btn_cancel.setStyleSheet(self.get_button_style("#dc3545"))  # Red
        self.btn_cancel.setMinimumHeight(40)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_verification)
        button_layout.addWidget(self.btn_cancel)
        
        button_layout.addStretch()
        
        self.btn_close = QtWidgets.QPushButton("Close")
        self.btn_close.setStyleSheet(self.get_button_style())
        self.btn_close.setMinimumHeight(40)
        self.btn_close.clicked.connect(self.accept)
        button_layout.addWidget(self.btn_close)
        
        layout.addLayout(button_layout)
    
    def apply_dark_theme(self):
        """Apply dark theme to the dialog."""
        self.setStyleSheet("""
            QDialog {
                background: #1a1a1a;
                color: #e8e8e8;
            }
            QLabel {
                color: #e8e8e8;
            }
            QScrollArea {
                border: none;
                background: #1a1a1a;
            }
        """)
    
    def get_group_style(self):
        """Get GroupBox styling."""
        return """
            QGroupBox {
                font-weight: 600;
                font-size: 13px;
                color: #e8e8e8;
                border: 2px solid #3a3a3a;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
            }
        """
    
    def get_input_style(self):
        """Get input field styling."""
        return """
            QLineEdit {
                background: #2a2a2a;
                border: 2px solid #3a3a3a;
                border-radius: 6px;
                padding: 10px;
                color: #e8e8e8;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #5a5a5a;
            }
        """
    
    def get_button_style(self, bg_color="#2a2a2a"):
        """Get button styling with optional background color."""
        return f"""
            QPushButton {{
                background: {bg_color};
                color: #e8e8e8;
                border: 2px solid #3a3a3a;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background: #3a3a3a;
                border-color: #5a5a5a;
            }}
            QPushButton:disabled {{
                background: #1a1a1a;
                color: #666;
                border-color: #2a2a2a;
            }}
        """
    
    def get_progress_style(self):
        """Get progress bar styling."""
        return """
            QProgressBar {
                border: 2px solid #3a3a3a;
                border-radius: 6px;
                text-align: center;
                background: #2a2a2a;
                color: #e8e8e8;
                font-weight: 600;
            }
            QProgressBar::chunk {
                background: #4a9eff;
                border-radius: 4px;
            }
        """
    
    def browse_image(self):
        """Browse for image file to verify."""
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select Image File to Verify",
            "",
            "Image Files (*.img *.dd *.raw *.E01 *.e01);;All Files (*.*)"
        )
        if filepath:
            self.file_input.setText(filepath)
            self.logger.info(f"Selected image for verification: {filepath}")
            
            # Check for corresponding report file
            report_path = Path(filepath).with_suffix('.txt')
            if report_path.exists():
                reply = QtWidgets.QMessageBox.question(
                    self,
                    "Report File Found",
                    f"Found corresponding report file:\n{report_path.name}\n\n"
                    "Would you like to load expected hash values from this report?",
                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
                )
                if reply == QtWidgets.QMessageBox.Yes:
                    self.load_hashes_from_file(str(report_path))
    
    def load_from_report(self):
        """Load expected hash values from a report file."""
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select Report File",
            "",
            "Text Files (*.txt);;All Files (*.*)"
        )
        if filepath:
            self.load_hashes_from_file(filepath)
    
    def load_hashes_from_file(self, filepath: str):
        """Parse report file and extract hash values."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            
            # Look for MD5
            md5_match = re.search(r'MD5\s*[:\s]+([a-fA-F0-9]{32})', content, re.IGNORECASE)
            if md5_match:
                self.expected_md5.setText(md5_match.group(1).lower())
                self.logger.info("Loaded MD5 from report file")
            
            # Look for SHA-1
            sha1_match = re.search(r'SHA-?1\s*[:\s]+([a-fA-F0-9]{40})', content, re.IGNORECASE)
            if sha1_match:
                self.expected_sha1.setText(sha1_match.group(1).lower())
                self.logger.info("Loaded SHA-1 from report file")
            
            # Look for SHA-256
            sha256_match = re.search(r'SHA-?256\s*[:\s]+([a-fA-F0-9]{64})', content, re.IGNORECASE)
            if sha256_match:
                self.expected_sha256.setText(sha256_match.group(1).lower())
                self.logger.info("Loaded SHA-256 from report file")
            
            if not (md5_match or sha1_match or sha256_match):
                QtWidgets.QMessageBox.warning(
                    self,
                    "No Hashes Found",
                    "Could not find any hash values in the report file."
                )
            
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self,
                "Error Loading Report",
                f"Failed to load report file:\n{str(e)}"
            )
            self.logger.error(f"Failed to load report file: {e}")
    
    def start_verification(self):
        """Start the verification process."""
        filepath = self.file_input.text().strip()
        
        if not filepath:
            QtWidgets.QMessageBox.warning(
                self,
                "No File Selected",
                "Please select an image file to verify."
            )
            return
        
        if not os.path.exists(filepath):
            QtWidgets.QMessageBox.warning(
                self,
                "File Not Found",
                f"The selected file does not exist:\n{filepath}"
            )
            return
        
        # Check if E01 without pyewf
        file_ext = Path(filepath).suffix.lower()
        is_e01 = file_ext in ['.e01', '.ex01', '.ewf', '.s01']
        
        if is_e01 and not HAS_PYEWF:
            reply = QtWidgets.QMessageBox.warning(
                self,
                "pyewf Not Available",
                "This is an E01 file but pyewf library is not installed.\n\n"
                "The hash will be calculated from the E01 CONTAINER,\n"
                "which will NOT match the source image hash!\n\n"
                "Install pyewf with: pip install libewf-python\n\n"
                "Continue anyway?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if reply != QtWidgets.QMessageBox.Yes:
                return
        
        self.logger.info(f"Starting verification: {filepath}")
        calculate_sha256 = self.sha256_check.isChecked()
        self.worker = VerificationWorker(filepath, calculate_sha256)
        
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        
        # Update UI
        self.btn_verify.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_close.setEnabled(False)
        self.file_input.setEnabled(False)
        self.sha256_check.setEnabled(False)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        
        # Disable copy buttons
        self.btn_copy_md5.setEnabled(False)
        self.btn_copy_sha1.setEnabled(False)
        self.btn_copy_sha256.setEnabled(False)
        self.btn_copy_all.setEnabled(False)
        
        self.worker.start()
    
    def on_progress(self, percent: int, status: str, speed: str):
        """Update progress display."""
        self.progress_bar.setValue(percent)
        self.status_label.setText(status)
        self.speed_label.setText(speed)
    
    def on_finished(self, results: dict):
        """Handle verification completion."""
        # Re-enable UI
        self.btn_verify.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_close.setEnabled(True)
        self.file_input.setEnabled(True)
        self.sha256_check.setEnabled(True)
        
        if results.get('error'):
            self.results_text.appendPlainText(f"\n❌ ERROR: {results['error']}")
            self.status_label.setText("Verification failed")
            self.logger.error(f"Verification error: {results['error']}")
            return
        
        # Store hashes for copy buttons
        self.calculated_hashes = {
            'md5': results['md5'],
            'sha1': results['sha1'],
            'sha256': results.get('sha256')
        }
        
        # Enable copy buttons
        self.btn_copy_md5.setEnabled(True)
        self.btn_copy_sha1.setEnabled(True)
        if results.get('sha256'):
            self.btn_copy_sha256.setEnabled(True)
        self.btn_copy_all.setEnabled(True)
        
        # Display calculated hashes
        elapsed = results.get('elapsed', 0)
        speed = (results['size'] / (1024 * 1024)) / max(0.01, elapsed) if elapsed > 0 else 0
        
        self.results_text.appendPlainText("=" * 50)
        self.results_text.appendPlainText("CALCULATED HASHES")
        self.results_text.appendPlainText("=" * 50)
        self.results_text.appendPlainText(f"MD5:     {results['md5']}")
        self.results_text.appendPlainText(f"SHA-1:   {results['sha1']}")
        if results.get('sha256'):
            self.results_text.appendPlainText(f"SHA-256: {results['sha256']}")
        self.results_text.appendPlainText("")
        self.results_text.appendPlainText(f"Time: {elapsed:.1f}s | Speed: {speed:.1f} MB/s")
        
        # Compare with expected values
        self.results_text.appendPlainText("")
        self.results_text.appendPlainText("=" * 50)
        self.results_text.appendPlainText("VERIFICATION RESULTS")
        self.results_text.appendPlainText("=" * 50)
        
        all_match = True
        any_compared = False
        
        # Check MD5
        expected_md5 = self.expected_md5.text().strip().lower()
        if expected_md5:
            any_compared = True
            if expected_md5 == results['md5'].lower():
                self.results_text.appendPlainText("✓ MD5 MATCH")
                self.logger.info("MD5 verification: MATCH")
            else:
                self.results_text.appendPlainText("✗ MD5 MISMATCH")
                self.results_text.appendPlainText(f"  Expected: {expected_md5}")
                self.results_text.appendPlainText(f"  Actual:   {results['md5']}")
                self.logger.warning("MD5 verification: MISMATCH")
                all_match = False
        
        # Check SHA-1
        expected_sha1 = self.expected_sha1.text().strip().lower()
        if expected_sha1:
            any_compared = True
            if expected_sha1 == results['sha1'].lower():
                self.results_text.appendPlainText("✓ SHA-1 MATCH")
                self.logger.info("SHA-1 verification: MATCH")
            else:
                self.results_text.appendPlainText("✗ SHA-1 MISMATCH")
                self.results_text.appendPlainText(f"  Expected: {expected_sha1}")
                self.results_text.appendPlainText(f"  Actual:   {results['sha1']}")
                self.logger.warning("SHA-1 verification: MISMATCH")
                all_match = False
        
        # Check SHA-256
        expected_sha256 = self.expected_sha256.text().strip().lower()
        if expected_sha256 and results.get('sha256'):
            any_compared = True
            if expected_sha256 == results['sha256'].lower():
                self.results_text.appendPlainText("✓ SHA-256 MATCH")
                self.logger.info("SHA-256 verification: MATCH")
            else:
                self.results_text.appendPlainText("✗ SHA-256 MISMATCH")
                self.results_text.appendPlainText(f"  Expected: {expected_sha256}")
                self.results_text.appendPlainText(f"  Actual:   {results['sha256']}")
                self.logger.warning("SHA-256 verification: MISMATCH")
                all_match = False
        
        # Final status
        if not any_compared:
            self.results_text.appendPlainText("")
            self.results_text.appendPlainText("No expected values provided for comparison.")
            self.results_text.appendPlainText("Hash calculation completed successfully.")
            self.status_label.setText("Hash calculation complete")
            self.logger.info("Hash calculation complete (no comparison)")
        elif all_match:
            self.results_text.appendPlainText("")
            self.results_text.appendPlainText("✓✓✓ IMAGE VERIFIED - ALL HASHES MATCH ✓✓✓")
            self.status_label.setText("✓ VERIFIED - Image integrity confirmed")
            self.logger.info("VERIFICATION PASSED")
            
            # Success popup
            QtWidgets.QMessageBox.information(
                self,
                "Verification Passed",
                "✓ Image verification PASSED!\n\n"
                "All hash values match the expected values.\n"
                "Image integrity is confirmed."
            )
        else:
            self.results_text.appendPlainText("")
            self.results_text.appendPlainText("✗✗✗ VERIFICATION FAILED - HASH MISMATCH ✗✗✗")
            self.status_label.setText("✗ FAILED - Hash mismatch detected")
            self.logger.warning("VERIFICATION FAILED")
            
            # Failure popup
            QtWidgets.QMessageBox.critical(
                self,
                "Verification Failed",
                "✗ Image verification FAILED!\n\n"
                "One or more hash values do not match.\n"
                "The image may have been modified or corrupted."
            )
    
    def copy_hash(self, hash_type: str):
        """Copy a specific hash to clipboard."""
        hash_value = self.calculated_hashes.get(hash_type)
        if hash_value:
            QtWidgets.QApplication.clipboard().setText(hash_value)
            self.logger.info(f"{hash_type.upper()} copied to clipboard")
    
    def copy_all_hashes(self):
        """Copy all hashes to clipboard."""
        lines = []
        if self.calculated_hashes.get('md5'):
            lines.append(f"MD5:     {self.calculated_hashes['md5']}")
        if self.calculated_hashes.get('sha1'):
            lines.append(f"SHA-1:   {self.calculated_hashes['sha1']}")
        if self.calculated_hashes.get('sha256'):
            lines.append(f"SHA-256: {self.calculated_hashes['sha256']}")
        
        if lines:
            QtWidgets.QApplication.clipboard().setText("\n".join(lines))
            self.logger.info("All hashes copied to clipboard")
    
    def cancel_verification(self):
        """Cancel the verification operation."""
        if self.worker:
            self.worker.cancel()
            self.status_label.setText("Cancelling...")
            self.logger.info("Verification cancelled by user")
