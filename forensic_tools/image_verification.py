"""
Image Verification Module
Hash verification and integrity checking for forensic images
"""

import os
import hashlib
import logging
from pathlib import Path
from PySide6 import QtCore, QtWidgets

from .utils import APP_TITLE

class VerificationWorker(QtCore.QThread):
    """
    Worker thread for image hash verification.
    Calculates MD5, SHA-1, and optionally SHA-256 hashes.
    """
    progress = QtCore.Signal(int, str, str)
    finished = QtCore.Signal(dict)
    
    def __init__(self, filepath: str, calculate_sha256: bool = False):
        super().__init__()
        self.filepath = filepath
        self.calculate_sha256 = calculate_sha256
        self.should_cancel = False
    
    def run(self):
        """Calculate hashes for the image file."""
        try:
            file_size = os.path.getsize(self.filepath)
            
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256() if self.calculate_sha256 else None
            
            bytes_read = 0
            chunk_size = 8 * 1024 * 1024
            
            import time
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
                            'size': file_size
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
                        
                        status = f"Calculating hashes... {bytes_read:,} / {file_size:,} bytes"
                        speed_str = f"{speed_mbps:.1f} MB/s"
                        
                        self.progress.emit(percent, status, speed_str)
                        last_update = current_time
            
            self.progress.emit(100, "Hash calculation complete", "")
            self.finished.emit({
                'md5': md5_hash.hexdigest(),
                'sha1': sha1_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest() if sha256_hash else None,
                'size': file_size,
                'error': None
            })
            
        except Exception as e:
            self.finished.emit({
                'error': str(e),
                'md5': None,
                'sha1': None,
                'sha256': None,
                'size': 0
            })
    
    def cancel(self):
        """Cancel the verification operation."""
        self.should_cancel = True

class ImageVerificationDialog(QtWidgets.QDialog):
    """
    Dialog for verifying forensic image integrity by recalculating hashes.
    Compares calculated hashes against expected values (manual entry or report file).
    """
    
    def __init__(self, parent: QtWidgets.QWidget, logger: logging.Logger):
        super().__init__(parent)
        self.logger = logger
        self.worker = None
        
        self.setWindowTitle(f"{APP_TITLE} - Image Verification")
        self.setModal(True)
        self.resize(1100, 700)
        self.setMinimumSize(900, 600)
        
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
            "Recalculate hashes for an existing image and compare against expected values"
        )
        subtitle.setStyleSheet("color: #e8e8e8;")
        layout.addWidget(subtitle)
        
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
        
        btn_load_report = QtWidgets.QPushButton("Load from Report File...")
        btn_load_report.setStyleSheet(self.get_button_style())
        btn_load_report.clicked.connect(self.load_from_report)
        expected_layout.addWidget(btn_load_report, 3, 1)
        
        layout.addWidget(expected_group)
        
        progress_group = QtWidgets.QGroupBox("Verification Progress")
        progress_group.setStyleSheet(self.get_group_style())
        progress_layout = QtWidgets.QVBoxLayout(progress_group)
        
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3d4148;
                border-radius: 6px;
                text-align: center;
                color: #e8e8e8;
                background: #2d3139;
                height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 #4caf50, stop:1 #388e3c);
                border-radius: 4px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QtWidgets.QLabel("Ready to verify")
        self.status_label.setStyleSheet("color: #e8e8e8;")
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
        results_group = QtWidgets.QGroupBox("Verification Results")
        results_group.setStyleSheet(self.get_group_style())
        results_layout = QtWidgets.QVBoxLayout(results_group)
        
        self.results_text = QtWidgets.QPlainTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            QPlainTextEdit {
                background:
                border: 2px solid
                border-radius: 6px;
                color:
                padding: 12px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
            }
        """)
        self.results_text.setMinimumHeight(120)
        results_layout.addWidget(self.results_text)
        
        layout.addWidget(results_group)
        
        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_verify = QtWidgets.QPushButton("Start Verification")
        self.btn_verify.setStyleSheet(self.get_button_style())
        self.btn_verify.setMinimumWidth(150)
        self.btn_verify.clicked.connect(self.start_verification)
        btn_layout.addWidget(self.btn_verify)
        
        self.btn_cancel = QtWidgets.QPushButton("Cancel")
        self.btn_cancel.setStyleSheet(self.get_button_style())
        self.btn_cancel.setMinimumWidth(100)
        self.btn_cancel.clicked.connect(self.cancel_verification)
        self.btn_cancel.setEnabled(False)
        btn_layout.addWidget(self.btn_cancel)
        
        btn_close = QtWidgets.QPushButton("Close")
        btn_close.setStyleSheet(self.get_button_style())
        btn_close.setMinimumWidth(100)
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)
    
    def apply_dark_theme(self):
        """Apply dark theme styling to dialog."""
        self.setStyleSheet("""
            QDialog {
                background:
            }
            QLabel {
                color:
            }
        """)
    
    def get_group_style(self):
        """Get GroupBox styling."""
        return """
            QGroupBox {
                font-weight: 600;
                font-size: 13px;
                color:
                border: 2px solid
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
                background:
                border: 2px solid
                border-radius: 6px;
                padding: 10px;
                color:
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color:
            }
        """
    
    def get_button_style(self):
        """Get button styling."""
        return """
            QPushButton {
                background:
                color:
                border: 2px solid
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 13px;
            }
            QPushButton:hover {
                background:
                border-color:
            }
            QPushButton:disabled {
                background:
                color:
                border-color:
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
            
            md5_match = re.search(r'MD5:\s*([0-9a-fA-F]{32})', content)
            if md5_match:
                self.expected_md5.setText(md5_match.group(1).lower())
            
            sha1_match = re.search(r'SHA-1:\s*([0-9a-fA-F]{40})', content)
            if sha1_match:
                self.expected_sha1.setText(sha1_match.group(1).lower())
            
            sha256_match = re.search(r'SHA-256:\s*([0-9a-fA-F]{64})', content)
            if sha256_match:
                self.expected_sha256.setText(sha256_match.group(1).lower())
                self.sha256_check.setChecked(True)
            
            self.logger.info(f"Loaded hash values from report: {filepath}")
            QtWidgets.QMessageBox.information(
                self,
                "Hashes Loaded",
                "Expected hash values have been loaded from the report file."
            )
            
        except Exception as e:
            self.logger.error(f"Failed to load report file: {e}")
            QtWidgets.QMessageBox.warning(
                self,
                "Load Failed",
                f"Failed to load hashes from report:\n{e}"
            )
    
    def start_verification(self):
        """Start image verification process."""
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
        
        self.logger.info(f"Starting verification of: {filepath}")
        self.results_text.clear()
        self.results_text.appendPlainText(f"Verifying: {filepath}\n")
        self.results_text.appendPlainText(f"File size: {os.path.getsize(filepath):,} bytes\n")
        
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3d4148;
                border-radius: 6px;
                text-align: center;
                color: #e8e8e8;
                background: #2d3139;
                height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 #4caf50, stop:1 #388e3c);
                border-radius: 4px;
            }
        """)
        
        self.btn_verify.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.file_input.setEnabled(False)
        self.sha256_check.setEnabled(False)
        
        self.worker = VerificationWorker(filepath, self.sha256_check.isChecked())
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()
    
    def cancel_verification(self):
        """Cancel ongoing verification."""
        if self.worker and self.worker.isRunning():
            self.logger.info("Cancelling verification...")
            self.worker.cancel()
            self.status_label.setText("Cancelling...")
    
    def on_progress(self, percent: int, status: str, speed: str):
        """Update progress display."""
        self.progress_bar.setValue(percent)
        status_text = status
        if speed:
            status_text += f" - {speed}"
        self.status_label.setText(status_text)
    
    def on_finished(self, result: dict):
        """Handle verification completion."""
        self.btn_verify.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.file_input.setEnabled(True)
        self.sha256_check.setEnabled(True)
        
        if result['error']:
            self.logger.error(f"Verification failed: {result['error']}")
            self.results_text.appendPlainText(f"\nERROR: {result['error']}")
            self.status_label.setText("Verification failed")
            
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: 2px solid #3d4148;
                    border-radius: 6px;
                    text-align: center;
                    color: #e8e8e8;
                    background: #2d3139;
                    height: 28px;
                }
                QProgressBar::chunk {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                               stop:0 #4caf50, stop:1 #388e3c);
                    border-radius: 4px;
                }
            """)
            
            QtWidgets.QMessageBox.critical(
                self,
                "Verification Failed",
                f"Failed to verify image:\n{result['error']}"
            )
            return
        
        self.results_text.appendPlainText("=== CALCULATED HASHES ===\n")
        self.results_text.appendPlainText(f"MD5:     {result['md5']}")
        self.results_text.appendPlainText(f"SHA-1:   {result['sha1']}")
        if result['sha256']:
            self.results_text.appendPlainText(f"SHA-256: {result['sha256']}")
        
        self.results_text.appendPlainText("\n=== VERIFICATION RESULTS ===\n")
        
        all_match = True
        any_compared = False
        
        expected_md5 = self.expected_md5.text().strip().lower()
        if expected_md5:
            any_compared = True
            if expected_md5 == result['md5']:
                self.results_text.appendPlainText("✓ MD5 MATCH")
                self.logger.info("MD5 verification: PASS")
            else:
                self.results_text.appendPlainText("✗ MD5 MISMATCH")
                self.results_text.appendPlainText(f"  Expected: {expected_md5}")
                self.results_text.appendPlainText(f"  Actual:   {result['md5']}")
                self.logger.warning("MD5 verification: FAIL")
                all_match = False
        
        expected_sha1 = self.expected_sha1.text().strip().lower()
        if expected_sha1:
            any_compared = True
            if expected_sha1 == result['sha1']:
                self.results_text.appendPlainText("✓ SHA-1 MATCH")
                self.logger.info("SHA-1 verification: PASS")
            else:
                self.results_text.appendPlainText("✗ SHA-1 MISMATCH")
                self.results_text.appendPlainText(f"  Expected: {expected_sha1}")
                self.results_text.appendPlainText(f"  Actual:   {result['sha1']}")
                self.logger.warning("SHA-1 verification: FAIL")
                all_match = False
        
        expected_sha256 = self.expected_sha256.text().strip().lower()
        if expected_sha256 and result['sha256']:
            any_compared = True
            if expected_sha256 == result['sha256']:
                self.results_text.appendPlainText("✓ SHA-256 MATCH")
                self.logger.info("SHA-256 verification: PASS")
            else:
                self.results_text.appendPlainText("✗ SHA-256 MISMATCH")
                self.results_text.appendPlainText(f"  Expected: {expected_sha256}")
                self.results_text.appendPlainText(f"  Actual:   {result['sha256']}")
                self.logger.warning("SHA-256 verification: FAIL")
                all_match = False
        
        if not any_compared:
            self.results_text.appendPlainText("\nNo expected values provided for comparison.")
            self.results_text.appendPlainText("Hash calculation completed successfully.")
            self.status_label.setText("Hash calculation complete (no comparison)")
            self.logger.info("Verification complete - no expected values provided")
            
        elif all_match:
            self.results_text.appendPlainText("\n✓✓✓ IMAGE VERIFIED - ALL HASHES MATCH ✓✓✓")
            self.status_label.setText("Verification PASSED - Image integrity confirmed")
            self.logger.info("Verification PASSED - all hashes match")
            
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: 2px solid #3d4148;
                    border-radius: 6px;
                    text-align: center;
                    color: #e8e8e8;
                    background: #2d3139;
                    height: 28px;
                }
                QProgressBar::chunk {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                               stop:0 #4caf50, stop:1 #388e3c);
                    border-radius: 4px;
                }
            """)
            
            QtWidgets.QMessageBox.information(
                self,
                "Verification Passed",
                "Image verification PASSED!\n\nAll hash values match the expected values.\n"
                "Image integrity is confirmed."
            )
        else:
            self.results_text.appendPlainText("\n✗✗✗ VERIFICATION FAILED - HASH MISMATCH ✗✗✗")
            self.status_label.setText("Verification FAILED - Hash mismatch detected")
            self.logger.warning("Verification FAILED - hash mismatch")
            
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: 2px solid #3d4148;
                    border-radius: 6px;
                    text-align: center;
                    color: #e8e8e8;
                    background: #2d3139;
                    height: 28px;
                }
                QProgressBar::chunk {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                               stop:0 #4caf50, stop:1 #388e3c);
                    border-radius: 4px;
                }
            """)
            
            QtWidgets.QMessageBox.critical(
                self,
                "Verification Failed",
                "Image verification FAILED!\n\n"
                "One or more hash values do not match.\n"
                "The image may have been modified or corrupted."
            )

