"""CSV and PDF report exports for SMB Sentinel."""
from __future__ import annotations
import csv
import io
from typing import Any


def export_csv(results: dict[str, dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    fields = ["ip", "risk_level", "findings", "port_open", "smb1_enabled",
              "smb2_supported", "smb2_dialect", "signing_enabled", "signing_required"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for ip, result in sorted(results.items()):
        row = {key: result.get(key, "") for key in fields if key != "ip"}
        row["ip"] = ip
        row["findings"] = "; ".join(result.get("findings", []))
        writer.writerow(row)
    return output.getvalue()


def export_pdf(results: dict[str, dict[str, Any]]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=12*mm, rightMargin=12*mm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SMB Sentinel — Configuration Review", styles["Title"]),
        Paragraph("Read-only SMB negotiation findings. Validate results with your administrator.", styles["Normal"]),
        Spacer(1, 6*mm),
    ]
    rows = [["IP address", "Risk", "SMBv1", "SMB2", "Dialect", "Signing enabled", "Signing required", "Findings"]]
    for ip, result in sorted(results.items()):
        rows.append([
            ip, str(result.get("risk_level", "unknown")).upper(),
            str(bool(result.get("smb1_enabled"))),
            str(bool(result.get("smb2_supported"))),
            str(result.get("smb2_dialect") or "N/A"),
            str(result.get("signing_enabled")),
            str(result.get("signing_required")),
            Paragraph("; ".join(result.get("findings", []))[:500], styles["BodyText"]),
        ])
    table = Table(rows, repeatRows=1, colWidths=[25*mm, 18*mm, 15*mm, 15*mm, 25*mm, 23*mm, 23*mm, 115*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#202833")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.35, colors.grey),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f1f4f7")]),
    ]))
    story.append(table)
    doc.build(story)
    return buffer.getvalue()
