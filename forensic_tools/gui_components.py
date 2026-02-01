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
ul {{ margin-left: 20px; margin-bottom: 12px; }}
.important {{ color: #e74c3c; font-weight: 600; }}
.success {{ color: #52c884; font-weight: 600; }}
.note {{ background: #2a2f3a; padding: 12px; border-left: 4px solid #4a90e2; margin: 12px 0; }}
</style></head>
<body>

<h2>Quick Start Guide</h2>
<p>This tool provides three main functions:</p>
<ul>
<li><strong>USB Write Protection:</strong> Registry-based write blocking for evidence preservation</li>
<li><strong>Forensic Disk Imaging:</strong> Bit-by-bit disk copies with MD5/SHA-1 verification</li>
<li><strong>Archive Image (E01):</strong> Convert raw images to court-accepted Expert Witness Format</li>
</ul>

<div class='note'>
<strong>Important:</strong> Administrator privileges are required for all operations. Always enable write protection before connecting evidence media.
</div>

<h2>USB Write Protection</h2>
<p>The write protection feature uses Windows Registry to block write operations to all USB devices:</p>

<h3>How to Use:</h3>
<ol>
<li>Click <strong>"Enable Write Protection"</strong> button</li>
<li>Status chip will turn <span class='success'>GREEN</span> when enabled</li>
<li>Connect USB evidence device</li>
<li>Imaging will be performed in read-only mode</li>
<li>Click <strong>"Disable Write Protection"</strong> when finished</li>
</ol>

<div class='note'>
<strong>Note:</strong> Write protection is <strong>automatically disabled</strong> when the application exits to prevent system issues.
</div>

<h3>Technical Details:</h3>
<p>Modifies registry key:<br>
<code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies</code><br>
Sets <code>WriteProtect = 1</code> (DWORD)</p>

<h2>Forensic Disk Imaging</h2>
<p>Create bit-by-bit forensic images of USB devices with cryptographic verification.</p>

<h3>Step-by-Step:</h3>
<ol>
<li><strong>Enable write protection</strong> (recommended)</li>
<li>Click <strong>"Create Forensic Image"</strong></li>
<li>Select source device from dropdown (removable USB only)</li>
<li>Click <strong>"Browse"</strong> to choose output location</li>
<li>Click <strong>"Start Imaging"</strong></li>
<li>Monitor progress (speed, ETA displayed)</li>
<li>Wait for hash calculation (MD5 + SHA-1)</li>
<li>Review forensic report (includes chain of custody)</li>
</ol>

<h3>Output Structure:</h3>
<pre>
YYYYMMDD_ImageName/
├── ImageName.img  # Bit-by-bit disk image
└── ImageName.txt  # Forensic report with hashes
</pre>

<h3>Features:</h3>
<ul>
<li>Real-time progress monitoring</li>
<li>Speed calculation (MB/s)</li>
<li>ETA estimation</li>
<li>MD5 and SHA-1 hash verification</li>
<li>Automated forensic reports</li>
<li>Cancel capability (creates partial image)</li>
</ul>

<h3>Typical Speeds:</h3>
<ul>
<li>USB 2.0: 20-35 MB/s</li>
<li>USB 3.0: 80-150 MB/s</li>
<li>USB 3.1: 150-300 MB/s</li>
</ul>

<h2>Archive Image (E01)</h2>
<p>Convert raw forensic images to Expert Witness Format (E01) - the industry standard for forensic evidence.</p>

<h3>Why E01 Format?</h3>
<ul>
<li><strong>Compression:</strong> Reduces storage requirements significantly</li>
<li><strong>Metadata:</strong> Embeds case number, examiner, notes directly in the file</li>
<li><strong>Court Accepted:</strong> Industry standard format recognized in legal proceedings</li>
<li><strong>Integrity:</strong> Built-in hash verification</li>
</ul>

<h3>How to Use:</h3>
<ol>
<li>Click <strong>"Archive Image (E01)"</strong> button</li>
<li>Select source image file (.img, .dd, or .raw)</li>
<li>Choose output location for .E01 file</li>
<li>Fill in case metadata (optional but recommended)</li>
<li>Select compression level (best recommended)</li>
<li>Click <strong>"Start Conversion"</strong></li>
</ol>

<h3>Compression Options:</h3>
<ul>
<li><strong>best:</strong> Maximum compression (recommended)</li>
<li><strong>fast:</strong> Faster conversion, less compression</li>
<li><strong>none:</strong> No compression (largest file)</li>
<li><strong>empty-block:</strong> Only compress empty blocks</li>
</ul>

<div class='note'>
<strong>Requirement:</strong> E01 conversion requires <code>ewfacquire.exe</code> from libewf. Download from <a href="https://github.com/libyal/libewf/releases">github.com/libyal/libewf</a> and place in <code>tsk_bin/</code> folder.
</div>

<h2>Troubleshooting</h2>

<h3>dd.exe Not Found</h3>
<p><span class='important'>Error:</span> "dd.exe not found in tsk_bin folder"</p>
<p><strong>Solution:</strong> Ensure dd.exe is placed in the <code>tsk_bin/</code> directory next to the application.</p>

<h3>ewfacquire.exe Not Found</h3>
<p><span class='important'>Error:</span> "ewfacquire.exe not found in tsk_bin folder"</p>
<p><strong>Solution:</strong> Download libewf from <a href="https://github.com/libyal/libewf/releases">github.com/libyal/libewf</a> and place <code>ewfacquire.exe</code> in the <code>tsk_bin/</code> directory.</p>

<h3>Write Protection Fails</h3>
<p><span class='important'>Error:</span> "Could not enable write-block"</p>
<p><strong>Solutions:</strong></p>
<ul>
<li>Right-click application → "Run as Administrator"</li>
<li>Check Windows User Account Control (UAC) settings</li>
<li>Verify no Group Policy restrictions</li>
</ul>

<h3>Device Not Detected</h3>
<p><span class='important'>Error:</span> No devices in dropdown</p>
<p><strong>Solutions:</strong></p>
<ul>
<li>Verify device is USB/removable (internal drives are filtered)</li>
<li>Click <strong>"Refresh"</strong> button</li>
<li>Check Windows Device Manager for driver issues</li>
<li>Reconnect USB device</li>
</ul>

<h3>Imaging Fails</h3>
<p><span class='important'>Error:</span> Operation fails partway through</p>
<p><strong>Solutions:</strong></p>
<ul>
<li>Check destination has sufficient free space</li>
<li>Verify source device health (may have bad sectors)</li>
<li>Ensure running as Administrator</li>
<li>Check dd.exe is valid executable</li>
</ul>

<h2>Best Practices</h2>

<h3>Before Imaging:</h3>
<ul>
<li><strong class='important'>Enable write protection FIRST</strong></li>
<li>Document case information</li>
<li>Photograph device and connections</li>
<li>Note device serial numbers</li>
</ul>

<h3>During Imaging:</h3>
<ul>
<li>Do not disconnect device</li>
<li>Ensure stable power supply</li>
<li>Monitor progress for errors</li>
<li>Do not use the computer for other tasks</li>
</ul>

<h3>After Imaging:</h3>
<ul>
<li>Verify hash values in report</li>
<li>Document chain of custody</li>
<li>Store original evidence securely</li>
<li>Create backup copies of images</li>
<li>Disable write protection</li>
</ul>

<h2>Chain of Custody</h2>
<p>Every operation generates a forensic report including:</p>
<ul>
<li>Timestamp (UTC)</li>
<li>Operator (Windows username)</li>
<li>System name</li>
<li>Device information</li>
<li>Operation timing and speed</li>
<li>Hash verification (MD5, SHA-1)</li>
<li>Notes section for manual entries</li>
</ul>

<p><strong>Preserve these reports</strong> for legal proceedings.</p>

<h2>About</h2>
<p><strong>{APP_TITLE}</strong><br>
Version: {APP_VERSION}<br>
Platform: Windows 10/11 (x64)</p>

<p><strong>Purpose:</strong> Professional forensic tool for law enforcement, incident response teams, and digital forensics professionals.</p>

<p><strong>Components:</strong></p>
<ul>
<li>dd.exe - GNU dd for Windows (disk imaging)</li>
<li>ewfacquire.exe - libewf (E01 creation)</li>
</ul>

<p><strong>License:</strong> MIT / GPL-3.0</p>

<h2>Legal Disclaimer & Warnings</h2>

<div class='note' style='background: #3a1f1f; border-left: 4px solid #e74c3c;'>
<strong style='color: #ff6b6b;'>IMPORTANT LEGAL NOTICES - READ CAREFULLY</strong>
</div>

<h3>No Warranty - Validate All Results</h3>
<p class='important'>THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. Users must independently validate all results, hash values, and forensic outputs. Do not rely solely on this tool's output for legal or investigative conclusions.</p>

<h3>User Responsibility</h3>
<ul>
<li><strong>Authorization Required:</strong> Always obtain proper legal authorization before imaging devices, capturing data, or accessing systems</li>
<li><strong>Verify Results:</strong> Independently verify all hash values, file integrity, and forensic reports using alternative tools</li>
<li><strong>Chain of Custody:</strong> Users are solely responsible for maintaining proper chain of custody documentation</li>
<li><strong>Legal Compliance:</strong> Ensure compliance with all applicable federal, state, local, and international laws</li>
<li><strong>Privacy Laws:</strong> Comply with data protection regulations (GDPR, CCPA, etc.) when handling personal information</li>
</ul>

<h3>Professional Use Only</h3>
<p>This tool is intended for use by trained forensic professionals, law enforcement personnel, and authorized incident response teams. Improper use may:</p>
<ul>
<li>Compromise evidence admissibility in court</li>
<li>Violate privacy laws and regulations</li>
<li>Result in civil or criminal liability</li>
<li>Damage systems or data</li>
</ul>

<h3>Limitation of Liability</h3>
<p>The developers and distributors of this software:</p>
<ul>
<li>Make no guarantees about the accuracy, reliability, or completeness of results</li>
<li>Are not responsible for any data loss, system damage, or legal consequences</li>
<li>Do not provide legal advice or forensic consulting services</li>
<li>Disclaim all liability for improper use or misinterpretation of results</li>
</ul>

<h3>Critical Warnings</h3>
<p class='important'><strong>ALWAYS:</strong></p>
<ul>
<li>Document all actions and maintain detailed logs</li>
<li>Create multiple backup copies of evidence</li>
<li>Verify hash values using independent tools (e.g., md5sum, sha1sum, FTK Imager)</li>
<li>Follow established forensic procedures and industry standards</li>
<li>Consult with legal counsel regarding admissibility requirements</li>
<li>Test procedures in non-production environments first</li>
</ul>

<p class='important'><strong>NEVER:</strong></p>
<ul>
<li>Image devices without proper authorization</li>
<li>Rely on a single tool for critical forensic work</li>
<li>Use this tool as your sole validation method</li>
<li>Access systems or data you're not authorized to examine</li>
<li>Assume all operations completed successfully without verification</li>
</ul>

<h3>Third-Party Components</h3>
<p>This tool incorporates third-party software (dd.exe, libewf) which are subject to their own licenses and limitations. Users must comply with all applicable licenses.</p>

<div class='note'>
<strong>BY USING THIS SOFTWARE, YOU ACKNOWLEDGE:</strong> You have read and understood these warnings, you accept full responsibility for validating results, you will use this tool only for legitimate and authorized purposes, and you agree to comply with all applicable laws and regulations.
</div>

<h2>Support</h2>
<p>For issues or feedback, use the thumbs down button below responses or contact your system administrator.</p>

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
