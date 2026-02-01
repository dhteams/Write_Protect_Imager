"""
PDF Report Generation Module
Convert forensic text reports to professional PDF format
"""

import os
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def is_pdf_available() -> bool:
    """Check if PDF generation is available."""
    return REPORTLAB_AVAILABLE


def generate_pdf_report(text_report_path: str, output_pdf_path: Optional[str] = None) -> str:
    """
    Convert a text forensic report to professional PDF format.
    
    Args:
        text_report_path: Path to the .txt report file
        output_pdf_path: Optional custom output path. If None, uses same name with .pdf extension
    
    Returns:
        Path to generated PDF file
    
    Raises:
        ImportError: If reportlab is not installed
        FileNotFoundError: If text report doesn't exist
        Exception: For other PDF generation errors
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF generation.\n"
            "Install with: pip install reportlab --break-system-packages"
        )
    
    if not os.path.exists(text_report_path):
        raise FileNotFoundError(f"Report file not found: {text_report_path}")
    
    # Determine output path
    if output_pdf_path is None:
        output_pdf_path = str(Path(text_report_path).with_suffix('.pdf'))
    
    # Read the text report
    with open(text_report_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Parse the report content
    report_data = _parse_report(content)
    
    # Create PDF
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    # Build the PDF content
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#2d3748'),
        spaceAfter=8,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        textColor=colors.HexColor('#4a5568'),
        fontName='Courier',
        leftIndent=20
    )
    
    # Title
    title = Paragraph(report_data.get('title', 'Forensic Report'), title_style)
    story.append(title)
    story.append(Spacer(1, 0.3*inch))
    
    # Add report sections
    sections = [
        'OPERATION DETAILS',
        'DEVICE INFORMATION',
        'RAM CAPTURE INFORMATION',
        'TIMING INFORMATION',
        'HASH VERIFICATION',
        'CHAIN OF CUSTODY NOTES'
    ]
    
    for section_name in sections:
        if section_name in report_data:
            # Section heading
            heading = Paragraph(section_name, heading_style)
            story.append(heading)
            
            # Section content
            section_content = report_data[section_name]
            
            if section_name == 'HASH VERIFICATION':
                # Special formatting for hash values
                hash_data = []
                for line in section_content:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        hash_data.append([key.strip(), value.strip()])
                
                if hash_data:
                    hash_table = Table(hash_data, colWidths=[1.5*inch, 4.5*inch])
                    hash_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f7fafc')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2d3748')),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTNAME', (1, 0), (1, -1), 'Courier'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                        ('TOPPADDING', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ]))
                    story.append(hash_table)
            else:
                # Regular content
                for line in section_content:
                    if line.strip():
                        if ':' in line:
                            # Key-value pair
                            p = Paragraph(line, body_style)
                            story.append(p)
                        else:
                            # Regular text
                            p = Paragraph(line, body_style)
                            story.append(p)
            
            story.append(Spacer(1, 0.2*inch))
    
    # Footer with generation info
    story.append(Spacer(1, 0.3*inch))
    footer_text = f"PDF generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    footer = Paragraph(footer_text, ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#718096'),
        alignment=TA_CENTER
    ))
    story.append(footer)
    
    # Build PDF
    doc.build(story)
    
    return output_pdf_path


def _parse_report(content: str) -> dict:
    """Parse text report content into structured sections."""
    sections = {}
    current_section = None
    current_content = []
    
    lines = content.split('\n')
    
    for line in lines:
        # Check if this is a title line
        if 'Forensic Imaging Report' in line or 'RAM Capture Report' in line:
            sections['title'] = line.strip()
            continue
        
        # Check if this is a section header
        stripped = line.strip()
        if stripped and not stripped.startswith('-') and not stripped.startswith('='):
            # Check for section headers (all caps with optional dashes)
            if stripped.replace('-', '').replace(' ', '').isupper() and len(stripped) > 5:
                # Save previous section
                if current_section:
                    sections[current_section] = current_content
                
                # Start new section
                current_section = stripped.replace('-', '').strip()
                current_content = []
                continue
        
        # Add content to current section
        if current_section and line.strip() and not line.strip().startswith('='):
            current_content.append(line.strip())
    
    # Save last section
    if current_section:
        sections[current_section] = current_content
    
    return sections


def convert_report_to_pdf(text_report_path: str) -> tuple[bool, str]:
    """
    Convert a forensic report to PDF with error handling.
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        pdf_path = generate_pdf_report(text_report_path)
        return True, pdf_path
    except ImportError as e:
        return False, str(e)
    except FileNotFoundError as e:
        return False, f"Report file not found: {e}"
    except Exception as e:
        return False, f"PDF generation failed: {e}"
