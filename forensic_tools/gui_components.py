"""
GUI Components Module
Shared UI components (HelpDialog, QtLogHandler)
"""

import logging
from PySide6 import QtCore, QtWidgets

from .utils import APP_TITLE, APP_VERSION


# ---------------- Qt Log Handler ----------------
class QtLogHandler(logging.Handler):
    """
    Thread-safe logging handler for Qt widgets.
    Uses QMetaObject.invokeMethod for cross-thread safety.
    """
    def __init__(self, widget):
        super().__init__()
        self.widget = widget
    
    def emit(self, record):
        try:
            msg = self.format(record)
            # Use QueuedConnection for thread safety
            QtCore.QMetaObject.invokeMethod(
                self.widget, "appendPlainText",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, msg)
            )
        except Exception:
            self.handleError(record)


# ---------------- Help Dialog ----------------
class HelpDialog(QtWidgets.QDialog):
    """
    Help dialog with comprehensive user documentation.
    """
    def __init__(self, parent: QtWidgets.QWidget):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_TITLE} - Help")
        self.setModal(True)
        self.resize(800, 700)
        
        # Apply dialog styling
        self.setStyleSheet("""
            QDialog {
                background: #1a1d23;
            }
            QTextEdit {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                color: #e8e8e8;
                padding: 16px;
                font-size: 12px;
                line-height: 1.6;
            }
            QPushButton {
                background: #2d3440;
                color: #e8e8e8;
                border: 2px solid #3a4150;
                border-radius: 8px;
                padding: 10px 24px;
                font-weight: 600;
                font-size: 13px;
            }
            QPushButton:hover {
                background: #363d4d;
                border-color: #4a5162;
            }
        """)
        
        if parent:
            parent_geo = parent.geometry()
            self.move(
                parent_geo.center().x() - self.width() // 2,
                parent_geo.center().y() - self.height() // 2
            )
        
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Help content
        help_text = f"""<html>
<head><style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }}
h2 {{ color: #4a90e2; margin-top: 24px; margin-bottom: 12px; }}
h3 {{ color: #7a8290; margin-top: 16px; margin-bottom: 8px; }}
p {{ margin-bottom: 12px; }}
ul, ol {{ margin-left: 20px; margin-bottom: 12px; }}
.important {{ color: #e74c3c; font-weight: 600; }}
.warning {{ background: #3a1f1f; padding: 12px; border-left: 4px solid #e74c3c; margin: 12px 0; }}
</style></head>
<body>

<h2>{APP_TITLE} {APP_VERSION}</h2>
<p>Professional forensic imaging tool for Windows 10/11 (x64).</p>

<h2>Quick Start Guide</h2>

<h3>1. Enable Write Protection</h3>
<ol>
<li>Click "Enable Write Protection"</li>
<li>Status turns GREEN when active</li>
<li>Connect USB evidence device</li>
</ol>

<h3>2. Create Forensic Image</h3>
<ol>
<li>Click "Create Forensic Image"</li>
<li>Select source device</li>
<li>Browse for output location</li>
<li>Fill case information (optional)</li>
<li>Scroll down and click "Start Imaging"</li>
</ol>

<h3>3. Archive to E01 (Optional)</h3>
<ol>
<li>Click "Archive Image (E01)"</li>
<li>Select the .img file created above</li>
<li>Choose output location</li>
<li>Click "Start Conversion"</li>
</ol>

<h3>4. Verify Image (Optional)</h3>
<ol>
<li>Click "Verify Image"</li>
<li>Select image file</li>
<li>Compare hashes with report</li>
</ol>

<h3>5. Secure Wipe (When Needed)</h3>
<ol>
<li>Click "Secure Wipe"</li>
<li>Select device to wipe</li>
<li>Confirm by typing "WIPE"</li>
</ol>

<h2>Features</h2>

<h3>USB Write Protection</h3>
<p>Triple-method registry-based write blocking. Prevents write operations to all USB devices. Automatically disabled on exit.</p>

<h3>Forensic Disk Imaging</h3>
<p>Bit-by-bit imaging with MD5, SHA-1, and optional SHA-256 hashes. Generates forensic reports with case information and chain of custody.</p>

<h3>E01 Archiving</h3>
<p>Converts raw images to Expert Witness Format. Supports compression and embedded metadata. Industry standard for legal proceedings.</p>

<h3>Image Verification</h3>
<p>Independent hash calculation for integrity verification.</p>

<h3>Secure Disk Wipe</h3>
<p>Zero-fill wipe with verification. Double confirmation required.</p>

<h2>Requirements</h2>
<ul>
<li>Windows 10/11 (x64)</li>
<li>Administrator privileges</li>
<li>dd.exe in tsk_bin folder</li>
<li>ewfacquire.exe in tsk_bin folder (for E01)</li>
</ul>

<h2>Legal</h2>

<div class='warning'>
<strong style='color: #ff6b6b;'>IMPORTANT - READ BEFORE USE</strong>
</div>

<h3>No Warranty</h3>
<p class='important'>THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. Users must independently validate all results.</p>

<h3>Authorization Required</h3>
<p>Obtain proper legal authorization before imaging devices or accessing systems. Comply with all applicable laws including data protection regulations.</p>

<h3>User Responsibility</h3>
<ul>
<li>Verify all hash values using independent tools</li>
<li>Maintain proper chain of custody documentation</li>
<li>Follow established forensic procedures</li>
</ul>

<h3>Limitation of Liability</h3>
<p>Developers make no guarantees about accuracy or completeness. Not responsible for data loss, system damage, or legal consequences.</p>

<h3>Permitted Use</h3>
<ul>
<li>Law enforcement</li>
<li>Incident response</li>
<li>Authorized forensic examination</li>
<li>Personal data recovery</li>
</ul>

<h3>Prohibited Use</h3>
<ul>
<li>Unauthorized access</li>
<li>Privacy violations</li>
<li>Data theft</li>
<li>Evidence tampering</li>
</ul>

<p><strong>License:</strong> MIT / GPL-3.0</p>

<p>By using this software, you accept full responsibility for validating results and complying with all applicable laws.</p>

</body>
</html>"""
        
        text_edit = QtWidgets.QTextEdit()
        text_edit.setHtml(help_text)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        
        # Close button
        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch()
        btn_close = QtWidgets.QPushButton("Close")
        btn_close.setMinimumWidth(100)
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)
