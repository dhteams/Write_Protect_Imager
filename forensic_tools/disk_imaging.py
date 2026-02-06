"""
Forensic Disk Imaging Module
dd-based disk imaging with progress monitoring and hash verification
"""

import os
import time
import hashlib
import subprocess
import datetime
import re
from typing import Optional, Dict
from pathlib import Path

from PySide6 import QtCore, QtWidgets

from .utils import IS_WINDOWS, write_report, find_dd_executable


# ---------------- Image Worker (dd-based) ----------------
class ImageWorker(QtCore.QThread):
    """
    Background worker thread for disk imaging using dd.
    
    Signals:
        progress(int, float, float): Progress percentage, speed (MB/s), ETA (seconds)
        log(str): Log messages
        finished_report(str, object): Report path and copied bytes on success
        partial_report(str, object): Report path and copied bytes on cancel/error
        hash_progress(int): Hash calculation progress percentage
    """
    progress = QtCore.Signal(int, float, float)
    log = QtCore.Signal(str)
    finished_report = QtCore.Signal(str, object)  # object to handle large file sizes (>2GB)
    partial_report = QtCore.Signal(str, object)   # object to handle large file sizes (>2GB)
    hash_progress = QtCore.Signal(int)

    def __init__(self, src: str, dst: str, expected: int, device_info: Dict, dd_path: str, metadata: Dict = None, calculate_sha256: bool = False, use_error_recovery: bool = False):
        super().__init__()
        self.src = src
        self.dst = dst
        self.expected = expected
        self._dev_info = device_info
        self.dd_path = dd_path
        self.metadata = metadata or {}
        self.calculate_sha256 = calculate_sha256
        self.use_error_recovery = use_error_recovery
        self.chunk = 4 * 1024 * 1024  # 4 MB chunks for hash calculation
        self.start_ts = time.time()
        self._cancel = False
        self._cancel_lock = QtCore.QMutex()  # Thread-safe lock for cancel flag
        self.process: Optional[subprocess.Popen] = None
        self._skip_hash = False  # Skip hashing on cancel

    def request_cancel(self, skip_hash: bool = False):
        """Request cancellation of the imaging operation (thread-safe)."""
        self._cancel_lock.lock()
        self._cancel = True
        self._skip_hash = skip_hash
        process_to_terminate = self.process
        self._cancel_lock.unlock()
        
        # Terminate outside the lock to avoid deadlock
        if process_to_terminate and process_to_terminate.poll() is None:
            try:
                process_to_terminate.terminate()
                # Wait up to 5 seconds for graceful termination
                try:
                    process_to_terminate.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if terminate didn't work
                    process_to_terminate.kill()
                    process_to_terminate.wait()
            except Exception:
                # Process already terminated or other error - safe to ignore
                pass

    def run(self):
        """Main thread execution."""
        if not self.dd_path:
            self.log.emit("[ERROR] dd.exe not found in tsk_bin folder")
            self.log.emit("[ERROR] Cannot perform imaging without dd")
            return
        
        self._run_dd()

    def _run_dd(self) -> None:
        """Execute dd command for imaging."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        copied = 0
        t0 = self.start_ts
        last = 0.0

        try:
            if os.path.exists(self.dst):
                self._finish_with_report("FAILED", 0, "", "", "", f"Destination exists: {self.dst}", "dd")
                return
            os.makedirs(os.path.dirname(self.dst) or ".", exist_ok=True)

            self.log.emit(f"[IMAGER] Using dd: {self.dd_path}")
            self.log.emit(f"[IMAGER] Source: {self.src}")
            self.log.emit(f"[IMAGER] Destination: {self.dst}")
            if self.expected:
                size_gb = self.expected/(1024**3)
                self.log.emit(f"[IMAGER] Size: {self.expected:,} bytes ({size_gb:.2f} GB)")
                if size_gb < 1.0:
                    self.log.emit(f"[IMAGER] Note: Small drive will complete in seconds")
            
            # Build dd command (status=progress not reliable on Windows)
            bs = "4M"
            cmd = [
                self.dd_path,
                f"if={self.src}",
                f"of={self.dst}",
                f"bs={bs}"
            ]
            if self.use_error_recovery:
                cmd.append("conv=noerror,sync")
            
            self.log.emit(f"[IMAGER] Command: {' '.join(cmd)}")
            self.log.emit(f"[IMAGER] Imaging in progress...")
            
            # Run dd process with exception handling
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
                )
            except FileNotFoundError:
                self.log.emit(f"[ERROR] dd.exe not found at: {self.dd_path}")
                self._finish_with_report("FAILED", 0, "", "", "dd.exe executable not found", "dd")
                return
            except PermissionError:
                self.log.emit(f"[ERROR] Permission denied executing dd.exe")
                self._finish_with_report("FAILED", 0, "", "", "Permission denied to execute dd.exe", "dd")
                return
            except Exception as e:
                self.log.emit(f"[ERROR] Failed to start imaging: {e}")
                self._finish_with_report("FAILED", 0, "", "", f"Failed to start dd process: {e}", "dd")
                return

            # Monitor by checking output file size (Windows dd doesn't output progress)
            milestones = set()
            last_size = 0
            stall_count = 0
            
            while self.process.poll() is None:
                # Check cancel flag with thread safety
                self._cancel_lock.lock()
                should_cancel = self._cancel
                self._cancel_lock.unlock()
                
                if should_cancel:
                    # Don't terminate here - request_cancel() already did it
                    break
                
                # Check output file size (with race condition protection)
                try:
                    if os.path.exists(self.dst):
                        copied = os.path.getsize(self.dst)
                        
                        # Detect stall
                        if copied == last_size:
                            stall_count += 1
                        else:
                            stall_count = 0
                        last_size = copied
                        
                        # Calculate progress
                        now = time.time()
                        if self.expected and copied > 0:
                            pct = min(100, int(copied * 100 / self.expected))
                            mbps = (copied / 1048576.0) / max(1e-6, (now - t0))
                            eta = max(0.0, ((self.expected - copied) / 1048576.0) / max(mbps, 1e-6))
                            
                            if now - last >= 0.5:
                                self.progress.emit(pct, mbps, eta)
                                last = now
                            if pct in (25, 50, 75) and pct not in milestones:
                                self.log.emit(f"[IMAGER] {pct}% complete")
                                milestones.add(pct)
                except (OSError, FileNotFoundError):
                    # File disappeared or can't be accessed - will retry next iteration
                    pass
                
                # Sleep briefly before next check
                time.sleep(0.3)

            exit_code = self.process.returncode

            # Final size check
            if os.path.exists(self.dst):
                copied = os.path.getsize(self.dst)

            # Check if cancelled (thread-safe)
            self._cancel_lock.lock()
            was_cancelled = self._cancel
            skip_hash = self._skip_hash
            self._cancel_lock.unlock()

            # Handle cancellation
            if was_cancelled:
                self.log.emit("[IMAGER] Cancelled by user")
                if skip_hash:
                    self.log.emit("[IMAGER] Skipping hash calculation")
                    self._finish_with_report("PARTIAL (user cancelled)", copied, "", "", "", method="dd")
                else:
                    # Calculate hashes even for partial
                    self.log.emit("[HASH] Calculating hashes of partial image...")
                    md5_hex, sha1_hex, sha256_hex = self._calculate_hashes_with_progress(copied)
                    self._finish_with_report("PARTIAL (user cancelled)", copied, md5_hex, sha1_hex, sha256_hex, method="dd")
                return

            # Handle dd error
            if exit_code != 0:
                self.log.emit(f"[IMAGER] dd exited with code {exit_code}")
                # Still calculate hashes
                self.log.emit("[HASH] Calculating hashes...")
                md5_hex, sha1_hex, sha256_hex = self._calculate_hashes_with_progress(copied)
                self._finish_with_report("PARTIAL (dd error)", copied, md5_hex, sha1_hex, sha256_hex,
                                       f"dd exited with code {exit_code}", "dd")
                return

            # Success - calculate hashes with progress
            self.log.emit("[HASH] Calculating hashes...")
            md5_hex, sha1_hex, sha256_hex = self._calculate_hashes_with_progress(copied)
            
            self.progress.emit(100, 0.0, 0.0)
            self.log.emit(f"[HASH] MD5    : {md5_hex}")
            self.log.emit(f"[HASH] SHA-1  : {sha1_hex}")
            if sha256_hex:
                self.log.emit(f"[HASH] SHA-256: {sha256_hex}")
            self._finish_with_report("COMPLETED", copied, md5_hex, sha1_hex, sha256_hex, method="dd")

        except Exception as e:
            self.log.emit(f"[ERROR] {e}")
            self._finish_with_report(
                "PARTIAL (error)" if copied > 0 else "FAILED",
                copied, "", "", "",
                f"Imaging error: {e!r}", "dd"
            )

    def _calculate_hashes_with_progress(self, file_size: int) -> tuple:
        """Calculate MD5, SHA-1, and optionally SHA-256 hashes with progress updates."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256() if self.calculate_sha256 else None
        
        if not os.path.exists(self.dst):
            return "", "", ""
        
        try:
            bytes_read = 0
            last_pct = -1
            
            with open(self.dst, "rb") as f:
                while True:
                    # Check for cancellation during hashing
                    self._cancel_lock.lock()
                    if self._cancel and self._skip_hash:
                        self._cancel_lock.unlock()
                        self.log.emit("[HASH] Hash calculation cancelled")
                        return md5.hexdigest(), sha1.hexdigest(), (sha256.hexdigest() if sha256 else "")
                    self._cancel_lock.unlock()
                    
                    chunk = f.read(self.chunk)
                    if not chunk:
                        break
                    
                    md5.update(chunk)
                    sha1.update(chunk)
                    if sha256:
                        sha256.update(chunk)
                    bytes_read += len(chunk)
                    
                    # Emit progress
                    if file_size > 0:
                        pct = int(bytes_read * 100 / file_size)
                        if pct != last_pct:
                            self.hash_progress.emit(pct)
                            last_pct = pct
            
            return md5.hexdigest(), sha1.hexdigest(), (sha256.hexdigest() if sha256 else "")
        except Exception as e:
            self.log.emit(f"[HASH] Error: {e}")
            return "", "", ""

    def _finish_with_report(self, status: str, copied: int, md5: str, sha1: str, sha256: str = "",
                           error_msg: str = "", method: str = "dd"):
        """Generate forensic report and emit appropriate signal."""
        end_ts = time.time()
        report_path = write_report(
            Path(self.dst), self._dev_info, self.start_ts, end_ts,
            self.expected, copied, md5, sha1, status, method, sha256,
            metadata=self.metadata
        )
        self.log.emit(f"[REPORT] {Path(report_path).name}")
        if error_msg:
            self.log.emit(f"[ERROR] {error_msg}")
        
        if "PARTIAL" in status or "FAILED" in status:
            self.partial_report.emit(report_path, copied)
        else:
            self.finished_report.emit(report_path, copied)


# ---------------- Imaging Dialog ----------------
class ImagingDialog(QtWidgets.QDialog):
    """
    Dialog for forensic disk imaging interface.
    Provides device selection, output location, progress monitoring, and controls.
    """
    
    def __init__(self, parent: QtWidgets.QWidget, blocker, logger):
        super().__init__(parent)
        self.setWindowTitle("Forensic Image Creation")
        self.setModal(True)
        self.resize(850, 750)
        
        self.blocker = blocker
        self.logger = logger
        self._worker: Optional[ImageWorker] = None
        self._dev_info: Dict = {}
        self._expected = 0
        self._cancel_dialog: Optional[QtWidgets.QProgressDialog] = None
        
        self._init_ui()
        self.refresh_devices()
    
    def _init_ui(self):
        """Initialize user interface."""
        # Styling
        self.setStyleSheet("""
            QDialog {
                background: #1a1d23;
            }
            QLabel {
                color: #e8e8e8;
                font-size: 13px;
            }
            QComboBox, QLineEdit {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                color: #e8e8e8;
                padding: 8px;
                font-size: 13px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 7px solid #7a8290;
                margin-right: 10px;
            }
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
                background: #363d4d;
                border-color: #4a5162;
            }
            QPushButton:disabled {
                background: #1e2129;
                color: #5a6270;
                border-color: #2a2f3a;
            }
            QProgressBar {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                text-align: center;
                color: #e8e8e8;
                font-weight: 600;
                height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 #4a90e2, stop:1 #357abd);
                border-radius: 4px;
            }
        """)
        
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create scroll area
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll.setStyleSheet("""
            QScrollArea {
                background: #1a1d23;
                border: none;
            }
            QScrollBar:vertical {
                background: #252932;
                width: 12px;
                border-radius: 6px;
                margin: 2px;
            }
            QScrollBar::handle:vertical {
                background: #4a5162;
                border-radius: 5px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #5a6272;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        # Content widget inside scroll area
        content_widget = QtWidgets.QWidget()
        content_widget.setStyleSheet("background: #1a1d23;")
        layout = QtWidgets.QVBoxLayout(content_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QtWidgets.QLabel("Forensic Disk Imaging")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #e8e8e8; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Device selection
        device_group = QtWidgets.QGroupBox("Source Device")
        device_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
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
        device_layout = QtWidgets.QVBoxLayout(device_group)
        
        dev_note = QtWidgets.QLabel("Select a removable USB device to image (internal drives are filtered):")
        dev_note.setStyleSheet("font-size: 12px; color: #a0a8b5;")
        device_layout.addWidget(dev_note)
        
        dev_row = QtWidgets.QHBoxLayout()
        self.cmb_phy = QtWidgets.QComboBox()
        self.cmb_phy.setMinimumWidth(400)
        dev_row.addWidget(self.cmb_phy, 1)
        
        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_refresh.setMaximumWidth(100)
        self.btn_refresh.clicked.connect(self.refresh_devices)
        dev_row.addWidget(self.btn_refresh)
        device_layout.addLayout(dev_row)
        
        layout.addWidget(device_group)
        
        # Output location
        output_group = QtWidgets.QGroupBox("Output Location")
        output_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
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
        output_layout = QtWidgets.QVBoxLayout(output_group)
        
        out_note = QtWidgets.QLabel("Output Location (creates YYYYMMDD_ImageName folder with .img + .txt report):")
        out_note.setStyleSheet("font-size: 12px; color: #a0a8b5;")
        output_layout.addWidget(out_note)
        
        out_row = QtWidgets.QHBoxLayout()
        self.dst_edit = QtWidgets.QLineEdit()
        self.dst_edit.setPlaceholderText("Click Browse to select output location...")
        out_row.addWidget(self.dst_edit, 1)
        
        self.btn_browse = QtWidgets.QPushButton("Browse...")
        self.btn_browse.setMaximumWidth(120)
        self.btn_browse.clicked.connect(self.choose_dest)
        out_row.addWidget(self.btn_browse)
        output_layout.addLayout(out_row)
        
        layout.addWidget(output_group)
        
        # Case Information
        case_group = QtWidgets.QGroupBox("Case Information (Optional)")
        case_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
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
        case_layout = QtWidgets.QGridLayout(case_group)
        case_layout.setSpacing(12)
        
        # Row 1: Case number, Evidence number
        case_layout.addWidget(QtWidgets.QLabel("Case Number:"), 0, 0)
        self.case_edit = QtWidgets.QLineEdit()
        self.case_edit.setPlaceholderText("e.g., CASE-2024-001")
        case_layout.addWidget(self.case_edit, 0, 1)
        
        case_layout.addWidget(QtWidgets.QLabel("Evidence Number:"), 0, 2)
        self.evidence_edit = QtWidgets.QLineEdit()
        self.evidence_edit.setPlaceholderText("e.g., EV-001")
        case_layout.addWidget(self.evidence_edit, 0, 3)
        
        # Row 2: Examiner
        case_layout.addWidget(QtWidgets.QLabel("Examiner:"), 1, 0)
        self.examiner_edit = QtWidgets.QLineEdit()
        try:
            import getpass
            self.examiner_edit.setText(getpass.getuser())
        except Exception:
            self.examiner_edit.setPlaceholderText("Your name")
        case_layout.addWidget(self.examiner_edit, 1, 1, 1, 3)
        
        # Row 3: Description (full width)
        case_layout.addWidget(QtWidgets.QLabel("Description:"), 2, 0)
        self.desc_edit = QtWidgets.QLineEdit()
        self.desc_edit.setPlaceholderText("Brief description of the evidence")
        case_layout.addWidget(self.desc_edit, 2, 1, 1, 3)
        
        # Row 4: Notes (full width)
        case_layout.addWidget(QtWidgets.QLabel("Notes:"), 3, 0, QtCore.Qt.AlignTop)
        self.notes_edit = QtWidgets.QTextEdit()
        self.notes_edit.setPlaceholderText("Additional notes for chain of custody...")
        self.notes_edit.setMaximumHeight(60)
        case_layout.addWidget(self.notes_edit, 3, 1, 1, 3)
        
        layout.addWidget(case_group)
        
        # Options
        options_group = QtWidgets.QGroupBox("Imaging Options")
        options_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
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
        options_layout = QtWidgets.QVBoxLayout(options_group)
        
        self.sha256_check = QtWidgets.QCheckBox("Calculate SHA-256 hash (slower but more secure)")
        self.sha256_check.setStyleSheet("color: #e8e8e8;")
        self.sha256_check.setChecked(False)
        self.sha256_check.setToolTip(
            "SHA-256 is more secure than MD5/SHA-1 but will increase imaging time by ~15-25%.\n"
            "MD5 and SHA-1 are always calculated regardless of this setting."
        )
        options_layout.addWidget(self.sha256_check)
        
        opt_note = QtWidgets.QLabel("Note: MD5 and SHA-1 are always calculated. SHA-256 adds ~15-25% to imaging time.")
        opt_note.setStyleSheet("font-size: 11px; color: #7a8290; margin-top: 4px;")
        options_layout.addWidget(opt_note)
        
        options_layout.addSpacing(12)
        
        self.error_recovery_check = QtWidgets.QCheckBox("Enable error recovery mode (skip bad sectors)")
        self.error_recovery_check.setStyleSheet("color: #e8e8e8;")
        self.error_recovery_check.setChecked(False)
        self.error_recovery_check.setToolTip(
            "Use dd with conv=noerror,sync for damaged drives.\n"
            "Continues past read errors, filling bad sectors with zeros.\n"
            "Slower than standard imaging but handles damaged media."
        )
        options_layout.addWidget(self.error_recovery_check)
        
        error_note = QtWidgets.QLabel("For damaged drives - continues past read errors, filling unreadable sectors with zeros.")
        error_note.setStyleSheet("font-size: 11px; color: #f59e0b; margin-top: 4px;")
        options_layout.addWidget(error_note)
        
        layout.addWidget(options_group)
        
        # Progress
        progress_group = QtWidgets.QGroupBox("Progress")
        progress_group.setStyleSheet("""
            QGroupBox {
                font-weight: 600;
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
        progress_layout = QtWidgets.QVBoxLayout(progress_group)
        
        self.pbar = QtWidgets.QProgressBar()
        self.pbar.setValue(0)
        progress_layout.addWidget(self.pbar)
        
        self.lbl_speed = QtWidgets.QLabel("Ready to image")
        self.lbl_speed.setStyleSheet("color: #a0a8b5; font-size: 12px;")
        self.lbl_speed.setAlignment(QtCore.Qt.AlignCenter)
        progress_layout.addWidget(self.lbl_speed)
        
        layout.addWidget(progress_group)
        
        # Buttons (inside scroll area - user scrolls to reach them)
        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_start = QtWidgets.QPushButton("Start Imaging")
        self.btn_start.setMinimumWidth(150)
        self.btn_start.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #4a90e2, stop:1 #357abd);
                border: 2px solid #2d7acc;
                color: white;
                font-weight: 700;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #5a9fef, stop:1 #4a90e2);
                border-color: #4a90e2;
            }
            QPushButton:disabled {
                background: #2a2f3a;
                border-color: #1e2129;
                color: #5a6270;
            }
        """)
        self.btn_start.clicked.connect(self.on_start)
        btn_layout.addWidget(self.btn_start)
        
        self.btn_cancel = QtWidgets.QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setMinimumWidth(120)
        self.btn_cancel.clicked.connect(self.on_cancel)
        btn_layout.addWidget(self.btn_cancel)
        
        self.btn_save = QtWidgets.QPushButton("Open Output Folder")
        self.btn_save.setMinimumWidth(180)
        self.btn_save.clicked.connect(self.open_output_folder)
        btn_layout.addWidget(self.btn_save)
        
        btn_layout.addStretch()
        
        self.btn_close_dlg = QtWidgets.QPushButton("Close")
        self.btn_close_dlg.setMinimumWidth(100)
        self.btn_close_dlg.clicked.connect(self.accept)
        btn_layout.addWidget(self.btn_close_dlg)
        
        layout.addLayout(btn_layout)
        
        # Finalize scroll area
        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll, 1)
    
    def refresh_devices(self):
        """Refresh list of physical devices."""
        from .usb_blocker import USBWriteBlocker
        
        self.cmb_phy.clear()
        self.logger.info("[DEVICES] Scanning for removable USB devices...")
        
        devs = USBWriteBlocker.list_physical()
        if not devs:
            self.cmb_phy.addItem("No removable devices found", None)
            self.logger.warning("[DEVICES] No removable USB devices detected")
        else:
            for dev in devs:
                idx = dev['index']
                size_bytes = dev['size']
                vendor = dev.get('vendor', '')
                product = dev.get('product', '')
                
                size_gb = size_bytes / (1024**3)
                
                # Include vendor/product in display if available
                device_name = f"PhysicalDrive{idx}"
                if vendor and product:
                    device_name += f" - {vendor} {product}"
                elif vendor:
                    device_name += f" - {vendor}"
                elif product:
                    device_name += f" - {product}"
                
                label = f"{device_name} - {size_gb:.2f} GB"
                self.cmb_phy.addItem(label, dev)  # Store entire dict as payload
                self.logger.info(f"[DEVICES] Found: {label}")
    
    def choose_dest(self):
        """Choose output location."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get device name from selection
        device_name = "ForensicImage"
        payload = self.cmb_phy.currentData()
        if isinstance(payload, dict):
            idx = payload['index']
            device_name = f"PhysicalDrive{idx}"
        else:
            # Fallback for old tuple format
            idx, size = payload
            device_name = f"PhysicalDrive{idx}"
        
        # Default filename - folder will be created automatically based on this name
        default_file = f"{timestamp}_{device_name}.img"
        
        desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
        start_dir = desktop if os.path.isdir(desktop) else os.getcwd()
        default_path = os.path.join(start_dir, default_file)
        
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save Forensic Image As (folder will be created automatically)",
            default_path,
            "Forensic Image Files (*.img);;Raw Image Files (*.raw *.dd);;All Files (*.*)"
        )
        
        if filepath:
            self.dst_edit.setText(filepath)
    
    def open_output_folder(self):
        """Open output folder in Explorer."""
        dst = self.dst_edit.text().strip()
        if not dst:
            QtWidgets.QMessageBox.information(self, "No Output", "No output location selected.")
            return
        
        folder = os.path.dirname(dst)
        try:
            if IS_WINDOWS:
                if os.path.exists(folder):
                    os.startfile(os.path.normpath(folder))
                else:
                    os.makedirs(folder, exist_ok=True)
                    os.startfile(os.path.normpath(folder))
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Open Folder", f"Unable to open folder:\n{e}")
    
    def on_start(self):
        """Start imaging process."""
        parent = self.parent()
        
        # Check write protection
        if not self.blocker.verify():
            self.logger.warning("[IMAGING] Write protection NOT enabled")
            yn = QtWidgets.QMessageBox.question(
                self, "Write Protection Disabled",
                "Write protection is currently DISABLED.\n\n"
                "For forensic integrity, write protection should be enabled "
                "BEFORE connecting evidence media.\n\n"
                "Enable write protection now?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if yn == QtWidgets.QMessageBox.Yes:
                if not parent.blocker.enable():
                    self.logger.error("Failed to enable write protection")
                    QtWidgets.QMessageBox.critical(self, "Error", "Could not enable write-block.")
                    return
                parent.refresh_status()
                self.logger.info("Write protection enabled successfully")
        
        payload = self.cmb_phy.currentData()
        if not isinstance(payload, dict):
            self.logger.warning("No physical drive selected")
            QtWidgets.QMessageBox.warning(self, "Missing Source", "Select a PhysicalDrive.")
            return
        
        # Extract all device info from dict
        idx = payload['index']
        size = payload['size']
        vendor = payload.get('vendor', '')
        product = payload.get('product', '')
        serial = payload.get('serial', '')
        
        self._expected = int(size or 0)
        
        # Store all device info
        self._dev_info['physical'] = idx
        self._dev_info['vendor'] = vendor
        self._dev_info['product'] = product
        self._dev_info['serial'] = serial
        
        self.logger.info(f"Selected device: PhysicalDrive{idx} ({size:,} bytes)")
        
        dst = self.dst_edit.text().strip()
        if not dst:
            self.logger.info("No output location selected - opening file browser")
            self.choose_dest()
            dst = self.dst_edit.text().strip()
            if not dst:
                self.logger.warning("User cancelled output location selection")
                return
        
        # Create folder structure based on image name
        # e.g., "C:\Desktop\evidence.img" becomes "C:\Desktop\evidence\evidence.img"
        dst_path = Path(dst)
        image_name = dst_path.stem  # Get filename without extension (e.g., "evidence")
        parent_dir = dst_path.parent  # Get parent directory
        image_ext = dst_path.suffix or ".img"  # Get extension, default to .img
        
        # Check if the image file is already in a folder with the same name
        if parent_dir.name != image_name:
            # Create new folder path
            image_folder = parent_dir / image_name
            dst = str(image_folder / f"{image_name}{image_ext}")
            self.dst_edit.setText(dst)
            self.logger.info(f"[IMAGING] Output folder: {image_folder}")
        
        self.logger.info(f"Output location: {dst}")
        
        if os.path.exists(dst):
            self.logger.warning(f"Output file already exists: {dst}")
            yn = QtWidgets.QMessageBox.question(
                self, "Overwrite?", f"{dst}\nexists. Overwrite?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if yn != QtWidgets.QMessageBox.Yes:
                self.logger.info("User cancelled overwrite")
                return
            try:
                os.remove(dst)
                self.logger.info(f"Deleted existing file: {dst}")
            except PermissionError:
                self.logger.error(f"Permission denied deleting file: {dst}")
                QtWidgets.QMessageBox.critical(
                    self, "Permission Denied",
                    f"Cannot delete existing file (permission denied):\n{dst}\n\n"
                    "File may be open in another program or you lack permissions."
                )
                return
            except Exception as e:
                self.logger.error(f"Error deleting file: {e}")
                QtWidgets.QMessageBox.critical(
                    self, "Cannot Delete File",
                    f"Cannot overwrite existing file:\n{dst}\n\nError: {e}"
                )
                return
        
        # Validate physical drive index
        if not isinstance(idx, int) or idx < 0 or idx > 31:
            self.logger.error(f"Invalid physical drive index: {idx}")
            QtWidgets.QMessageBox.critical(
                self, "Invalid Device",
                f"Invalid physical drive index: {idx}\n\nExpected value between 0 and 31."
            )
            return
        
        # Check for dd.exe
        dd_path = find_dd_executable()
        if not dd_path:
            self.logger.error("dd.exe not found in tsk_bin folder")
            QtWidgets.QMessageBox.critical(
                self, "dd.exe Not Found",
                "dd.exe not found in tsk_bin folder.\n\n"
                "Please ensure dd.exe is placed in:\n"
                "tsk_bin/dd.exe"
            )
            return
        
        self.logger.info(f"Found dd.exe at: {dd_path}")
        
        src = f"\\\\.\\PhysicalDrive{idx}"
        calculate_sha256 = self.sha256_check.isChecked()
        use_error_recovery = self.error_recovery_check.isChecked()
        
        # Gather case metadata from UI fields
        metadata = {
            "case_number": self.case_edit.text().strip(),
            "evidence_number": self.evidence_edit.text().strip(),
            "examiner": self.examiner_edit.text().strip(),
            "description": self.desc_edit.text().strip(),
            "notes": self.notes_edit.toPlainText().strip(),
        }
        
        self.logger.info(f"[IMAGING] Starting disk imaging operation")
        self.logger.info(f"[IMAGING] Source: {src}")
        self.logger.info(f"[IMAGING] Destination: {dst}")
        self.logger.info(f"[IMAGING] Expected size: {self._expected:,} bytes")
        self.logger.info(f"[IMAGING] SHA-256 calculation: {'ENABLED' if calculate_sha256 else 'DISABLED'}")
        self.logger.info(f"[IMAGING] Error recovery mode: {'ENABLED' if use_error_recovery else 'DISABLED'}")
        if metadata["case_number"]:
            self.logger.info(f"[IMAGING] Case: {metadata['case_number']}")
        if metadata["evidence_number"]:
            self.logger.info(f"[IMAGING] Evidence: {metadata['evidence_number']}")
        
        self._worker = ImageWorker(src, dst, self._expected, self._dev_info, dd_path, metadata, calculate_sha256, use_error_recovery)
        self._worker.progress.connect(self.on_progress)
        self._worker.log.connect(self.logger.info)
        self._worker.finished_report.connect(self.on_finished)
        self._worker.partial_report.connect(self.on_partial)
        self._worker.hash_progress.connect(self.on_hash_progress)
        
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_save.setEnabled(False)
        self.cmb_phy.setEnabled(False)
        self.dst_edit.setEnabled(False)
        self.btn_close_dlg.setEnabled(False)
        self.sha256_check.setEnabled(False)
        self.error_recovery_check.setEnabled(False)
        # Disable case info fields during imaging
        self.case_edit.setEnabled(False)
        self.evidence_edit.setEnabled(False)
        self.examiner_edit.setEnabled(False)
        self.desc_edit.setEnabled(False)
        self.notes_edit.setEnabled(False)
        
        self._worker.start()
        self.logger.info("[IMAGING] Worker thread started")
    
    def on_cancel(self) -> None:
        """Request cancellation of imaging."""
        if self._worker:
            self.logger.info("[IMAGING] User requested cancellation")
            
            # Ask if they want to hash the partial image
            reply = QtWidgets.QMessageBox.question(
                self, "Cancel Imaging",
                "Do you want to calculate hashes of the partial image?\n\n"
                "Yes - Calculate hashes (takes time)\n"
                "No - Skip hashes (faster)",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No | QtWidgets.QMessageBox.Cancel
            )
            
            if reply == QtWidgets.QMessageBox.Cancel:
                return
            
            skip_hash = (reply == QtWidgets.QMessageBox.No)
            
            self.btn_cancel.setText("Cancelling...")
            self.btn_cancel.setEnabled(False)
            self.logger.info("Cancellation requested - finishing current operation...")
            
            if not skip_hash:
                # Show cancellation progress dialog for hashing
                self._cancel_dialog = QtWidgets.QProgressDialog(
                    "Cancelling imaging...\n\nCalculating hashes of partial image...",
                    None,  # No cancel button
                    0, 100,
                    self
                )
                self._cancel_dialog.setWindowTitle("Cancelling")
                self._cancel_dialog.setWindowModality(QtCore.Qt.WindowModal)
                self._cancel_dialog.setMinimumDuration(0)
                self._cancel_dialog.setCancelButton(None)
                self._cancel_dialog.show()
            
            self._worker.request_cancel(skip_hash=skip_hash)
    
    def on_progress(self, pct: int, mbps: float, eta: float) -> None:
        """Update progress bar and status text."""
        self.pbar.setValue(pct)
        if pct < 100:
            self.lbl_speed.setText(f"{pct}% complete | {mbps:.1f} MB/s | ETA: {int(eta)}s")
        else:
            self.lbl_speed.setText("Imaging complete, calculating hashes...")
    
    def on_hash_progress(self, pct: int) -> None:
        """Update hash calculation progress."""
        self.lbl_speed.setText(f"Calculating hashes: {pct}%")
        # Update cancel dialog if it exists
        if hasattr(self, '_cancel_dialog') and self._cancel_dialog:
            self._cancel_dialog.setValue(pct)
            self._cancel_dialog.setLabelText(f"Calculating hashes of partial image: {pct}%")
    
    def on_finished(self, report_path: str, copied) -> None:
        """Handle successful completion."""
        self.pbar.setValue(100)
        self.lbl_speed.setText("Imaging completed successfully!")
        self.lbl_speed.setStyleSheet("color: #52c884; font-size: 12px; font-weight: 600;")
        
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setText("Cancel")
        self.btn_save.setEnabled(True)
        self.cmb_phy.setEnabled(True)
        self.dst_edit.setEnabled(True)
        self.btn_close_dlg.setEnabled(True)
        self.sha256_check.setEnabled(True)
        self.error_recovery_check.setEnabled(True)
        # Re-enable case info fields
        self.case_edit.setEnabled(True)
        self.evidence_edit.setEnabled(True)
        self.examiner_edit.setEnabled(True)
        self.desc_edit.setEnabled(True)
        self.notes_edit.setEnabled(True)
        
        size_gb = copied / (1024**3)
        self.logger.info(f"[IMAGING] Completed successfully: {size_gb:.2f} GB ({copied:,} bytes)")
        self.logger.info(f"[IMAGING] Report saved: {Path(report_path).name}")
        
        QtWidgets.QMessageBox.information(
            self, "Imaging Complete",
            f"Forensic image created successfully!\n\n"
            f"Size: {size_gb:.2f} GB ({copied:,} bytes)\n\n"
            f"Report: {Path(report_path).name}"
        )
    
    def on_partial(self, report_path: str, copied) -> None:
        """Handle cancelled or partial completion."""
        # Close the cancelling dialog if it exists
        if hasattr(self, '_cancel_dialog') and self._cancel_dialog:
            self._cancel_dialog.close()
            self._cancel_dialog = None
        
        self.pbar.setValue(0)
        self.lbl_speed.setText("Imaging cancelled or incomplete")
        self.lbl_speed.setStyleSheet("color: #f5a742; font-size: 12px; font-weight: 600;")
        
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setText("Cancel")
        self.btn_save.setEnabled(True)
        self.cmb_phy.setEnabled(True)
        self.dst_edit.setEnabled(True)
        self.btn_close_dlg.setEnabled(True)
        self.sha256_check.setEnabled(True)
        self.error_recovery_check.setEnabled(True)
        # Re-enable case info fields
        self.case_edit.setEnabled(True)
        self.evidence_edit.setEnabled(True)
        self.examiner_edit.setEnabled(True)
        self.desc_edit.setEnabled(True)
        self.notes_edit.setEnabled(True)
        
        # Use absolute value to ensure positive display
        copied_abs = abs(copied)
        size_gb = copied_abs / (1024**3)
        
        self.logger.info(f"[IMAGING] Operation cancelled/partial: {size_gb:.2f} GB ({copied_abs:,} bytes)")
        self.logger.info(f"[IMAGING] Partial report saved: {Path(report_path).name}")
        
        QtWidgets.QMessageBox.warning(
            self, "Imaging Cancelled",
            f"Imaging cancelled by user.\n\n"
            f"Partial image saved: {size_gb:.2f} GB ({copied_abs:,} bytes)\n\n"
            f"Report location:\n{report_path}"
        )
