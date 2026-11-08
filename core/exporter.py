"""
OctoRecon Export Utilities
Generates professional CSV and PDF intelligence reports.
"""

import csv
import io
from pathlib import Path
from typing import Any, Dict, List, Union

def export_to_csv(report_data: Dict[str, Any], output_path: Union[str, Path] = None) -> str:
    """Exports all module findings and table rows into structured CSV format."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header metadata
    writer.writerow(["OCTORECON RECONNAISSANCE REPORT"])
    writer.writerow(["Target", report_data.get("target", "Unknown")])
    writer.writerow(["Grade", report_data.get("grade", "N/A")])
    writer.writerow(["Total Score", f"{report_data.get('total_score', 0)}/{report_data.get('max_potential_score', 0)}"])
    writer.writerow(["Scan Time", report_data.get("scan_time", "")])
    writer.writerow([])
    
    # Module Results
    writer.writerow(["Module", "Property / Column", "Value / Finding", "Score", "Description"])
    modules = report_data.get("modules", {})
    for mod_name, mod in modules.items():
        score_str = f"{mod.get('score', 0)}/{mod.get('max_score', 0)}"
        desc = mod.get("description", "")
        rows = mod.get("data", [])
        
        if not rows:
            writer.writerow([mod_name, "-", "No findings or empty dataset", score_str, desc])
            continue
            
        for row in rows:
            if isinstance(row, dict):
                # Flatten dict row
                for k, v in row.items():
                    writer.writerow([mod_name, str(k), str(v), score_str, desc])
            elif isinstance(row, (list, tuple)):
                writer.writerow([mod_name, "Item", ", ".join(map(str, row)), score_str, desc])
            else:
                writer.writerow([mod_name, "Content", str(row), score_str, desc])

    csv_content = output.getvalue()
    if output_path:
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_content)
    return csv_content

def export_to_pdf(report_data: Dict[str, Any], output_path: Union[str, Path]) -> bool:
    """Generates an executive-style PDF security assessment report using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    except ImportError:
        return False

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=14
    )
    h2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )
    table_cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )

    story = []
    
    # 1. Cover / Executive Summary Header
    story.append(Paragraph("OctoRecon Security Intelligence Report", title_style))
    story.append(Paragraph(f"Target: <b>{report_data.get('target', 'Unknown')}</b> | Generated: {report_data.get('scan_time', '')}", subtitle_style))
    story.append(Spacer(1, 10))
    
    grade = report_data.get("grade", "N/A")
    total_score = report_data.get("total_score", 0)
    max_score = report_data.get("max_potential_score", 0)
    
    grade_color = colors.HexColor("#16a34a") if "A" in grade else (colors.HexColor("#d97706") if "B" in grade or "C" in grade else colors.HexColor("#dc2626"))
    
    summary_data = [
        ["Target Assessment", "Overall Grade", "Security Posture Score"],
        [report_data.get("target", "N/A"), grade, f"{total_score} / {max_score}"]
    ]
    summary_table = Table(summary_data, colWidths=[240, 150, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TEXTCOLOR', (1, 1), (1, 1), grade_color),
        ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
        ('FONTSIZE', (1, 1), (1, 1), 16),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))
    
    # Notes if any
    notes = report_data.get("grading_notes", "")
    if notes:
        story.append(Paragraph(f"<b>Key Security Observation:</b> {notes}", body_style))
        story.append(Spacer(1, 10))

    # 2. Module Findings Section
    story.append(Paragraph("Detailed Module Findings", h2_style))
    story.append(Spacer(1, 5))

    modules = report_data.get("modules", {})
    for mod_name, mod in modules.items():
        score_str = f"Score: {mod.get('score', 0)}/{mod.get('max_score', 0)}"
        desc = mod.get("description", "")
        
        mod_header = [
            [Paragraph(f"<b>{mod_name}</b>", body_style), Paragraph(f"<b>{score_str}</b>", body_style)]
        ]
        mh_table = Table(mod_header, colWidths=[400, 140])
        mh_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ]))
        story.append(mh_table)
        
        if desc:
            story.append(Paragraph(f"<i>{desc}</i>", body_style))
            story.append(Spacer(1, 3))
            
        rows = mod.get("data", [])
        if rows:
            # Build mini-table
            table_rows = []
            # Extract sample columns
            first_row = rows[0]
            if isinstance(first_row, dict):
                cols = list(first_row.keys())[:4]  # limit to 4 cols for PDF width
                header_row = [Paragraph(f"<b>{c}</b>", table_cell_style) for c in cols]
                table_rows.append(header_row)
                
                for r in rows[:15]:  # limit top 15 findings per module to keep PDF crisp
                    row_cells = [Paragraph(str(r.get(c, "-")), table_cell_style) for c in cols]
                    table_rows.append(row_cells)
            
            if table_rows:
                num_cols = len(table_rows[0])
                col_w = 540 / max(num_cols, 1)
                t = Table(table_rows, colWidths=[col_w] * num_cols)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ]))
                story.append(t)
        
        story.append(Spacer(1, 8))

    doc.build(story)
    return True
