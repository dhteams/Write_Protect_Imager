"""
E01 Archive Module
Convert raw disk images (.img/.dd/.raw) to Expert Witness Format (E01)
Includes hash verification of source image and zip packaging
"""

import os
import time
import hashlib
import subprocess
import zipfile
import datetime
import getpass
import socket
import re
from typing import Optional, Dict
from pathlib import Path

from PySide6 import QtCore, QtWidgets

from .utils import IS_WINDOWS, find_ewfacquire_executable


# ---------------- E01 Converter Worker ----------------
class E01Worker(QtCore.QThread):
    """
    Background worker thread for converting raw images to E01 format.
    
    Process:
    1. Calculate MD5/SHA-1 of SOURCE image (matches original dd hashes)
    2. Convert to E01 format
    3. Generate verification report
    4. Zip E01 + report together
    
    Signals:
        progress(int, str): Progress percentage and stage description
        log(str): Log messages
        finished(str): Output zip path on success
        failed(str): Error message on failure
    """
    progress = QtCore.Signal(int, str)
    log = QtCore.Signal(str)
    finished = QtCore.Signal(str)
    failed = QtCore.Signal(str)

    def __init__(self, src: str, dst: str, metadata: Dict, ewf_path: str, compression: str = "best"):
        super().__init__()
        self.src = src
        self.dst = dst
        self.metadata = metadata
        self.ewf_path = ewf_path
        self.compression = compression
        self.chunk = 4 * 1024 * 1024  # 4 MB chunks for hash calculation
        self.start_ts = time.time()
        self._cancel = False
        self._cancel_lock = QtCore.QMutex()
        self.process: Optional[subprocess.Popen] = None

    def request_cancel(self):
        """Request cancellation of the conversion."""
        self._cancel_lock.lock()
        self._cancel = True
        process_to_terminate = self.process
        self._cancel_lock.unlock()
        
        if process_to_terminate and process_to_terminate.poll() is None:
            try:
                process_to_terminate.terminate()
                try:
                    process_to_terminate.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process_to_terminate.kill()
                    process_to_terminate.wait()
            except Exception:
                pass

    def _is_cancelled(self) -> bool:
        """Check if cancellation requested (thread-safe)."""
        self._cancel_lock.lock()
        result = self._cancel
        self._cancel_lock.unlock()
        return result

    def run(self):
        """Execute the E01 conversion with hashing and packaging."""
        try:
            if not os.path.exists(self.src):
                self.failed.emit(f"Source file not found: {self.src}")
                return
            
            src_size = os.path.getsize(self.src)
            src_size_gb = src_size / (1024**3)
            
            self.log.emit(f"[E01] Source: {self.src}")
            self.log.emit(f"[E01] Size: {src_size:,} bytes ({src_size_gb:.2f} GB)")
            self.log.emit(f"[E01] Compression: {self.compression}")
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(self.dst) or ".", exist_ok=True)
            
            # ===== STAGE 1: Hash source image (0-40%) =====
            self.log.emit("[HASH] Calculating hashes of source image...")
            self.progress.emit(0, "Calculating source image hashes...")
            
            md5_hex, sha1_hex = self._calculate_source_hashes(src_size)
            
            if self._is_cancelled():
                self.failed.emit("Cancelled by user")
                return
            
            self.log.emit(f"[HASH] Source MD5  : {md5_hex}")
            self.log.emit(f"[HASH] Source SHA-1: {sha1_hex}")
            
            # ===== STAGE 2: Convert to E01 (40-90%) =====
            self.log.emit("[E01] Starting E01 conversion...")
            self.progress.emit(40, "Converting to E01 format...")
            
            e01_path = self._convert_to_e01()
            
            if self._is_cancelled():
                self._cleanup_partial(e01_path)
                self.failed.emit("Cancelled by user")
                return
            
            if not e01_path or not os.path.exists(e01_path):
                self.failed.emit("E01 conversion failed - output file not created")
                return
            
            e01_size = os.path.getsize(e01_path)
            e01_size_gb = e01_size / (1024**3)
            compression_ratio = (1 - e01_size / src_size) * 100 if src_size > 0 else 0
            
            self.log.emit(f"[E01] E01 size: {e01_size:,} bytes ({e01_size_gb:.2f} GB)")
            self.log.emit(f"[E01] Compression: {compression_ratio:.1f}% reduction")
            
            # ===== STAGE 3: Generate report (90-95%) =====
            self.progress.emit(90, "Generating verification report...")
            self.log.emit("[REPORT] Generating verification report...")
            
            report_path = self._generate_report(
                src_size, e01_path, e01_size,
                md5_hex, sha1_hex, compression_ratio
            )
            
            # ===== STAGE 4: Create zip archive (95-100%) =====
            self.progress.emit(95, "Creating zip archive...")
            self.log.emit("[ZIP] Creating archive package...")
            
            zip_path = self._create_zip_archive(e01_path, report_path)
            
            if not zip_path or not os.path.exists(zip_path):
                self.failed.emit("Failed to create zip archive")
                return
            
            zip_size = os.path.getsize(zip_path)
            zip_size_gb = zip_size / (1024**3)
            
            # Clean up individual files (keep only zip)
            try:
                os.remove(e01_path)
                os.remove(report_path)
                self.log.emit("[CLEANUP] Removed individual E01 and report files")
            except Exception as e:
                self.log.emit(f"[CLEANUP] Warning: Could not remove temp files: {e}")
            
            self.log.emit(f"[ZIP] Archive created: {zip_path}")
            self.log.emit(f"[ZIP] Archive size: {zip_size:,} bytes ({zip_size_gb:.2f} GB)")
            
            self.progress.emit(100, "Complete!")
            self.finished.emit(zip_path)
            
        except Exception as e:
            self.log.emit(f"[ERROR] {e}")
            self.failed.emit(f"Conversion error: {e}")

    def _calculate_source_hashes(self, file_size: int) -> tuple:
        """Calculate MD5 and SHA-1 hashes of source image with progress."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        
        bytes_read = 0
        last_pct = -1
        
        with open(self.src, "rb") as f:
            while True:
                if self._is_cancelled():
                    return md5.hexdigest(), sha1.hexdigest()
                
                chunk = f.read(self.chunk)
                if not chunk:
                    break
                
                md5.update(chunk)
                sha1.update(chunk)
                bytes_read += len(chunk)
                
                # Progress: 0-40% for hashing
                if file_size > 0:
                    hash_pct = int(bytes_read * 40 / file_size)
                    if hash_pct != last_pct:
                        self.progress.emit(hash_pct, f"Hashing source: {hash_pct * 100 // 40}%")
                        last_pct = hash_pct
        
        return md5.hexdigest(), sha1.hexdigest()

    def _convert_to_e01(self) -> Optional[str]:
        """Convert source image to E01 format using ewfacquire."""
        # Remove .E01 extension for target (ewfacquire adds it)
        target = self.dst
        if target.upper().endswith('.E01'):
            target = target[:-4]
        
        # Normalize paths for Windows (use backslashes)
        target_win = os.path.normpath(target)
        src_win = os.path.normpath(self.src)
        
        # Map compression names to ewfacquire values
        compression_map = {
            "best": "best",
            "fast": "fast",
            "none": "none",
            "empty-block": "empty-block"
        }
        comp = compression_map.get(self.compression, "best")
        
        cmd = [
            self.ewf_path,
            "-t", target_win,           # Target file (without extension)
            "-c", comp,                  # Compression
            "-f", "encase6",             # Format (encase6 = E01)
            "-m", "fixed",               # Media type
            "-M", "logical",             # Media flags
            "-S", "0",                   # Segment size (0 = no splitting)
            "-u",                        # Unattended mode
            "-q",                        # Quiet mode
        ]
        
        # Add metadata if provided
        if self.metadata.get("case_number"):
            cmd.extend(["-C", self.metadata["case_number"]])
        if self.metadata.get("description"):
            cmd.extend(["-D", self.metadata["description"]])
        if self.metadata.get("examiner"):
            cmd.extend(["-e", self.metadata["examiner"]])
        if self.metadata.get("evidence_number"):
            cmd.extend(["-E", self.metadata["evidence_number"]])
        if self.metadata.get("notes"):
            cmd.extend(["-N", self.metadata["notes"]])
        
        # Source file last
        cmd.append(src_win)
        
        self.log.emit(f"[E01] Command: {' '.join(cmd)}")
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
            )
        except FileNotFoundError:
            self.log.emit(f"[ERROR] ewfacquire.exe not found at: {self.ewf_path}")
            return None
        except Exception as e:
            self.log.emit(f"[ERROR] Failed to start ewfacquire: {e}")
            return None
        
        # Monitor progress
        last_pct = 40
        while self.process.poll() is None:
            if self._is_cancelled():
                return None
            
            line = self.process.stdout.readline()
            if line:
                line = line.strip()
                # Parse progress from ewfacquire output
                # Typical format: "Status: at 45%" or "acquired 45%"
                if "%" in line:
                    try:
                        # Extract percentage - try different formats
                        match = re.search(r'(\d+(?:\.\d+)?)\s*%', line)
                        if match:
                            ewf_pct = int(float(match.group(1)))
                            # Map ewfacquire 0-100% to our 40-90%
                            overall_pct = 40 + int(ewf_pct * 50 / 100)
                            if overall_pct != last_pct:
                                self.progress.emit(overall_pct, f"Converting: {ewf_pct}%")
                                last_pct = overall_pct
                    except (ValueError, IndexError):
                        pass
                
                # Log important lines
                if any(x in line.lower() for x in ["error", "warning", "complete", "acquired", "written"]):
                    self.log.emit(f"[E01] {line}")
        
        exit_code = self.process.returncode
        
        if exit_code != 0:
            self.log.emit(f"[E01] ewfacquire exited with code {exit_code}")
            # Try to read any remaining output for error details
            remaining = self.process.stdout.read()
            if remaining:
                for line in remaining.strip().split('\n'):
                    if line.strip():
                        self.log.emit(f"[E01] {line.strip()}")
            return None
        
        # Check for output file (ewfacquire creates .E01)
        output_file = target_win + ".E01"
        if os.path.exists(output_file):
            return output_file
        
        # Also check lowercase
        output_file_lower = target_win + ".e01"
        if os.path.exists(output_file_lower):
            return output_file_lower
            
        return None

    def _generate_report(self, src_size: int, e01_path: str, e01_size: int,
                        md5_hex: str, sha1_hex: str, compression_ratio: float) -> str:
        """Generate verification report."""
        end_ts = time.time()
        duration = end_ts - self.start_ts
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = Path(e01_path).stem + "_E01_Report.txt"
        report_path = os.path.join(os.path.dirname(e01_path), report_name)
        
        # Get system info
        try:
            operator = getpass.getuser()
        except Exception:
            operator = "Unknown"
        
        try:
            system_name = socket.gethostname()
        except Exception:
            system_name = "Unknown"
        
        src_size_gb = src_size / (1024**3)
        e01_size_gb = e01_size / (1024**3)
        
        lines = [
            "=" * 70,
            "E01 ARCHIVE VERIFICATION REPORT",
            "=" * 70,
            "",
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Operator: {operator}",
            f"System: {system_name}",
            "",
            "-" * 70,
            "SOURCE IMAGE",
            "-" * 70,
            f"File: {self.src}",
            f"Size: {src_size:,} bytes ({src_size_gb:.2f} GB)",
            "",
            "-" * 70,
            "SOURCE IMAGE HASHES (matches original forensic image)",
            "-" * 70,
            f"MD5:    {md5_hex}",
            f"SHA-1:  {sha1_hex}",
            "",
            "-" * 70,
            "E01 ARCHIVE",
            "-" * 70,
            f"File: {Path(e01_path).name}",
            f"Size: {e01_size:,} bytes ({e01_size_gb:.2f} GB)",
            f"Compression: {self.compression}",
            f"Space Saved: {compression_ratio:.1f}%",
            "",
            "-" * 70,
            "CASE METADATA",
            "-" * 70,
            f"Case Number: {self.metadata.get('case_number', 'N/A')}",
            f"Evidence Number: {self.metadata.get('evidence_number', 'N/A')}",
            f"Examiner: {self.metadata.get('examiner', 'N/A')}",
            f"Description: {self.metadata.get('description', 'N/A')}",
            f"Notes: {self.metadata.get('notes', 'N/A')}",
            "",
            "-" * 70,
            "CONVERSION DETAILS",
            "-" * 70,
            f"Start Time: {datetime.datetime.fromtimestamp(self.start_ts).strftime('%Y-%m-%d %H:%M:%S')}",
            f"End Time: {datetime.datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)",
            f"Tool: ewfacquire (libewf)",
            "",
            "-" * 70,
            "VERIFICATION INSTRUCTIONS",
            "-" * 70,
            "To verify this E01 archive matches the original evidence:",
            "",
            "1. Extract the E01 back to raw format using ewfexport:",
            f"   ewfexport -t extracted_image {Path(e01_path).name}",
            "",
            "2. Calculate hashes of the extracted image:",
            "   certutil -hashfile extracted_image.raw MD5",
            "   certutil -hashfile extracted_image.raw SHA1",
            "",
            "3. Compare with hashes above - they should match exactly.",
            "",
            "=" * 70,
            "END OF REPORT",
            "=" * 70,
        ]
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        
        self.log.emit(f"[REPORT] Created: {report_name}")
        return report_path

    def _create_zip_archive(self, e01_path: str, report_path: str) -> Optional[str]:
        """Create zip archive containing E01 and report."""
        zip_name = Path(e01_path).stem + "_Archive.zip"
        zip_path = os.path.join(os.path.dirname(e01_path), zip_name)
        
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add E01 file
                zf.write(e01_path, Path(e01_path).name)
                self.log.emit(f"[ZIP] Added: {Path(e01_path).name}")
                
                # Add report
                zf.write(report_path, Path(report_path).name)
                self.log.emit(f"[ZIP] Added: {Path(report_path).name}")
            
            return zip_path
        except Exception as e:
            self.log.emit(f"[ZIP] Error creating archive: {e}")
            return None

    def _cleanup_partial(self, e01_path: Optional[str]):
        """Clean up partial files on cancellation."""
        if e01_path and os.path.exists(e01_path):
            try:
                os.remove(e01_path)
                self.log.emit(f"[CLEANUP] Removed partial E01 file")
            except Exception:
                pass


# ---------------- E01 Archive Dialog ----------------
class E01ArchiveDialog(QtWidgets.QDialog):
    """
    Dialog for converting raw images to E01 format.
    """
    
    def __init__(self, parent: QtWidgets.QWidget, logger):
        super().__init__(parent)
        self.setWindowTitle("Archive Image to E01")
        self.setModal(True)
        self.resize(700, 650)
        
        self.logger = logger
        self._worker: Optional[E01Worker] = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize user interface."""
        self.setStyleSheet("""
            QDialog {
                background: #1a1d23;
            }
            QLabel {
                color: #e8e8e8;
                font-size: 13px;
            }
            QLineEdit, QTextEdit, QComboBox {
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
        
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Title
        title = QtWidgets.QLabel("Archive Image to E01 Format")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #e8e8e8; margin-bottom: 8px;")
        layout.addWidget(title)
        
        subtitle = QtWidgets.QLabel(
            "Convert raw forensic images (.img, .dd, .raw) to Expert Witness Format (E01)\n"
            "Hashes are calculated from source image to match original forensic hashes"
        )
        subtitle.setStyleSheet("font-size: 12px; color: #a0a8b5;")
        layout.addWidget(subtitle)
        
        # Source file selection
        src_group = QtWidgets.QGroupBox("Source Image")
        src_layout = QtWidgets.QHBoxLayout(src_group)
        
        self.src_edit = QtWidgets.QLineEdit()
        self.src_edit.setPlaceholderText("Select source .img, .dd, or .raw file...")
        src_layout.addWidget(self.src_edit, 1)
        
        self.btn_browse_src = QtWidgets.QPushButton("Browse...")
        self.btn_browse_src.setMaximumWidth(100)
        self.btn_browse_src.clicked.connect(self.choose_source)
        src_layout.addWidget(self.btn_browse_src)
        
        layout.addWidget(src_group)
        
        # Output location
        dst_group = QtWidgets.QGroupBox("Output Location")
        dst_layout = QtWidgets.QVBoxLayout(dst_group)
        
        dst_row = QtWidgets.QHBoxLayout()
        self.dst_edit = QtWidgets.QLineEdit()
        self.dst_edit.setPlaceholderText("Select output location...")
        dst_row.addWidget(self.dst_edit, 1)
        
        self.btn_browse_dst = QtWidgets.QPushButton("Browse...")
        self.btn_browse_dst.setMaximumWidth(100)
        self.btn_browse_dst.clicked.connect(self.choose_dest)
        dst_row.addWidget(self.btn_browse_dst)
        dst_layout.addLayout(dst_row)
        
        dst_note = QtWidgets.QLabel("Output will be a .zip file containing the E01 image and verification report")
        dst_note.setStyleSheet("font-size: 11px; color: #7a8290;")
        dst_layout.addWidget(dst_note)
        
        layout.addWidget(dst_group)
        
        # Metadata group
        meta_group = QtWidgets.QGroupBox("Case Metadata (Optional)")
        meta_layout = QtWidgets.QGridLayout(meta_group)
        meta_layout.setSpacing(12)
        
        # Row 1: Case number, Evidence number
        meta_layout.addWidget(QtWidgets.QLabel("Case Number:"), 0, 0)
        self.case_edit = QtWidgets.QLineEdit()
        self.case_edit.setPlaceholderText("e.g., CASE-2024-001")
        meta_layout.addWidget(self.case_edit, 0, 1)
        
        meta_layout.addWidget(QtWidgets.QLabel("Evidence Number:"), 0, 2)
        self.evidence_edit = QtWidgets.QLineEdit()
        self.evidence_edit.setPlaceholderText("e.g., EV-001")
        meta_layout.addWidget(self.evidence_edit, 0, 3)
        
        # Row 2: Examiner, Compression
        meta_layout.addWidget(QtWidgets.QLabel("Examiner:"), 1, 0)
        self.examiner_edit = QtWidgets.QLineEdit()
        self.examiner_edit.setPlaceholderText("Your name")
        meta_layout.addWidget(self.examiner_edit, 1, 1)
        
        meta_layout.addWidget(QtWidgets.QLabel("Compression:"), 1, 2)
        self.compression_combo = QtWidgets.QComboBox()
        self.compression_combo.addItems(["best", "fast", "none", "empty-block"])
        meta_layout.addWidget(self.compression_combo, 1, 3)
        
        # Row 3: Description (full width)
        meta_layout.addWidget(QtWidgets.QLabel("Description:"), 2, 0)
        self.desc_edit = QtWidgets.QLineEdit()
        self.desc_edit.setPlaceholderText("Brief description of the evidence")
        meta_layout.addWidget(self.desc_edit, 2, 1, 1, 3)
        
        # Row 4: Notes (full width)
        meta_layout.addWidget(QtWidgets.QLabel("Notes:"), 3, 0, QtCore.Qt.AlignTop)
        self.notes_edit = QtWidgets.QTextEdit()
        self.notes_edit.setPlaceholderText("Additional notes...")
        self.notes_edit.setMaximumHeight(60)
        meta_layout.addWidget(self.notes_edit, 3, 1, 1, 3)
        
        layout.addWidget(meta_group)
        
        # Progress
        progress_group = QtWidgets.QGroupBox("Progress")
        progress_layout = QtWidgets.QVBoxLayout(progress_group)
        
        self.pbar = QtWidgets.QProgressBar()
        self.pbar.setValue(0)
        progress_layout.addWidget(self.pbar)
        
        self.lbl_status = QtWidgets.QLabel("Ready to convert")
        self.lbl_status.setStyleSheet("color: #a0a8b5; font-size: 12px;")
        self.lbl_status.setAlignment(QtCore.Qt.AlignCenter)
        progress_layout.addWidget(self.lbl_status)
        
        layout.addWidget(progress_group)
        
        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_start = QtWidgets.QPushButton("Start Conversion")
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
        self.btn_cancel.setMinimumWidth(100)
        self.btn_cancel.clicked.connect(self.on_cancel)
        btn_layout.addWidget(self.btn_cancel)
        
        btn_layout.addStretch()
        
        self.btn_close = QtWidgets.QPushButton("Close")
        self.btn_close.setMinimumWidth(100)
        self.btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(self.btn_close)
        
        layout.addLayout(btn_layout)
    
    def choose_source(self):
        """Choose source image file."""
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select Source Image",
            "",
            "Forensic Images (*.img *.dd *.raw);;All Files (*.*)"
        )
        if filepath:
            self.src_edit.setText(filepath)
            
            # Auto-fill destination (as .zip)
            base = os.path.splitext(filepath)[0]
            self.dst_edit.setText(base + "_Archive.zip")
    
    def choose_dest(self):
        """Choose output file location."""
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save Archive As",
            self.dst_edit.text() or "",
            "ZIP Archives (*.zip);;All Files (*.*)"
        )
        if filepath:
            if not filepath.lower().endswith('.zip'):
                filepath += ".zip"
            self.dst_edit.setText(filepath)
    
    def on_start(self):
        """Start conversion process."""
        src = self.src_edit.text().strip()
        dst = self.dst_edit.text().strip()
        
        if not src:
            QtWidgets.QMessageBox.warning(self, "Missing Source", "Please select a source image file.")
            return
        
        if not os.path.exists(src):
            QtWidgets.QMessageBox.warning(self, "File Not Found", f"Source file not found:\n{src}")
            return
        
        if not dst:
            QtWidgets.QMessageBox.warning(self, "Missing Destination", "Please select an output location.")
            return
        
        # Check for ewfacquire
        ewf_path = find_ewfacquire_executable()
        if not ewf_path:
            QtWidgets.QMessageBox.critical(
                self, "ewfacquire Not Found",
                "ewfacquire.exe not found in tsk_bin folder.\n\n"
                "Please download libewf tools and place ewfacquire.exe in:\n"
                "tsk_bin/ewfacquire.exe\n\n"
                "Download from: https://github.com/libyal/libewf/releases"
            )
            return
        
        # Check if output exists
        if os.path.exists(dst):
            yn = QtWidgets.QMessageBox.question(
                self, "Overwrite?",
                f"Output file already exists:\n{dst}\n\nOverwrite?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if yn != QtWidgets.QMessageBox.Yes:
                return
            try:
                os.remove(dst)
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Cannot Delete", f"Cannot delete existing file:\n{e}")
                return
        
        # Ensure dst has .zip extension
        # If user manually edited it or it's malformed, fix it
        if not dst.lower().endswith('.zip'):
            # dst might be:
            # - Just a folder path
            # - A file path without extension
            # Build proper ZIP filename from source
            src_basename = os.path.splitext(os.path.basename(src))[0]
            # If dst looks like a folder (no extension), join with filename
            if not os.path.splitext(dst)[1]:
                dst = os.path.join(dst, f"{src_basename}_Archive.zip")
            else:
                # Has some extension but not .zip - replace it
                dst = os.path.splitext(dst)[0] + ".zip"
        
        # Derive E01 path from zip path
        e01_dst = dst.replace("_Archive.zip", ".E01").replace(".zip", ".E01")
        if not e01_dst.upper().endswith('.E01'):
            e01_dst = os.path.splitext(dst)[0] + ".E01"
        
        # Gather metadata
        metadata = {
            "case_number": self.case_edit.text().strip(),
            "evidence_number": self.evidence_edit.text().strip(),
            "examiner": self.examiner_edit.text().strip(),
            "description": self.desc_edit.text().strip(),
            "notes": self.notes_edit.toPlainText().strip(),
        }
        
        compression = self.compression_combo.currentText()
        
        self.logger.info("=" * 50)
        self.logger.info("=== E01 ARCHIVE CONVERSION ===")
        self.logger.info("=" * 50)
        
        # Create and start worker
        self._worker = E01Worker(src, e01_dst, metadata, ewf_path, compression)
        self._worker.progress.connect(self.on_progress)
        self._worker.log.connect(self.logger.info)
        self._worker.finished.connect(self.on_finished)
        self._worker.failed.connect(self.on_failed)
        
        # Disable controls
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_close.setEnabled(False)
        self.src_edit.setEnabled(False)
        self.dst_edit.setEnabled(False)
        self.btn_browse_src.setEnabled(False)
        self.btn_browse_dst.setEnabled(False)
        
        self.lbl_status.setText("Starting...")
        self.lbl_status.setStyleSheet("color: #a0a8b5; font-size: 12px;")
        
        self._worker.start()
    
    def on_cancel(self):
        """Cancel conversion."""
        if self._worker:
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setText("Cancelling...")
            self._worker.request_cancel()
    
    def on_progress(self, pct: int, stage: str):
        """Update progress bar and status."""
        self.pbar.setValue(pct)
        self.lbl_status.setText(stage)
    
    def on_finished(self, zip_path: str):
        """Handle successful conversion."""
        self.pbar.setValue(100)
        self.lbl_status.setText("Conversion complete!")
        self.lbl_status.setStyleSheet("color: #52c884; font-size: 12px; font-weight: 600;")
        
        self._reset_controls()
        
        zip_size = os.path.getsize(zip_path) if os.path.exists(zip_path) else 0
        zip_size_gb = zip_size / (1024**3)
        
        self.logger.info(f"[E01] Archive created: {zip_path}")
        
        QtWidgets.QMessageBox.information(
            self, "Conversion Complete",
            f"E01 archive created successfully!\n\n"
            f"Output: {Path(zip_path).name}\n"
            f"Size: {zip_size_gb:.2f} GB ({zip_size:,} bytes)\n\n"
            f"Contains:\n"
            f"  - E01 compressed image\n"
            f"  - Verification report with source hashes"
        )
    
    def on_failed(self, error: str):
        """Handle conversion failure."""
        self.pbar.setValue(0)
        self.lbl_status.setText("Conversion failed")
        self.lbl_status.setStyleSheet("color: #e74c3c; font-size: 12px; font-weight: 600;")
        
        self._reset_controls()
        
        self.logger.error(f"[E01] Conversion failed: {error}")
        
        QtWidgets.QMessageBox.warning(
            self, "Conversion Failed",
            f"E01 conversion failed:\n\n{error}"
        )
    
    def _reset_controls(self):
        """Re-enable controls after conversion."""
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setText("Cancel")
        self.btn_close.setEnabled(True)
        self.src_edit.setEnabled(True)
        self.dst_edit.setEnabled(True)
        self.btn_browse_src.setEnabled(True)
        self.btn_browse_dst.setEnabled(True)
