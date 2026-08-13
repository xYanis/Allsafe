"""
services/inventory_export.py
Export PDF de l'inventaire complet (patrimoine IT) — lecture seule, aucune
écriture sur les serveurs. Utilisé par GET /api/reports/inventory/pdf.
"""
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from models import Asset

_HEADER_BG = colors.HexColor("#161b22")
_ROW_ALT_BG = colors.HexColor("#f6f8fa")
_GRID_COLOR = colors.HexColor("#d0d7de")


def _format_disks(disks: list | None) -> str:
    if not disks:
        return "—"
    return ", ".join(f"{d.get('name', '?')} {d.get('total_gb', '?')} Go" for d in disks)


def _table_style(header_rows: int = 1) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, header_rows - 1), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, header_rows - 1), colors.white),
        ("FONTNAME", (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRID_COLOR),
        ("ROWBACKGROUNDS", (0, header_rows), (-1, -1), [colors.white, _ROW_ALT_BG]),
    ])


def build_inventory_pdf(assets: list[Asset]) -> bytes:
    """
    Tableau récapitulatif unique (nom, OS, CPU, architecture, cœurs, RAM,
    disques, nombre d'applications) — un actif par ligne, format paysage pour
    la largeur.

    La colonne "Apps" ne porte que le **nombre exact** d'applications
    installées. Le détail nom + version par actif a existé en appendice
    (28/07/2026) puis a été retiré le jour même à la demande de l'utilisateur :
    il gonflait le document (17 pages pour 2 actifs réellement scannés, et le
    parc en compte 72) sans servir l'usage visé. Le détail reste consultable à
    l'écran via `PackagesModal` (Inventaire.jsx).
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        topMargin=15 * mm, bottomMargin=15 * mm, leftMargin=12 * mm, rightMargin=12 * mm,
        title="Allsafe — Inventaire complet",
    )
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle("cell", parent=styles["Normal"], fontSize=8, leading=10)

    generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    elements = [
        Paragraph("Allsafe — Inventaire complet du parc", styles["Title"]),
        Paragraph(f"{len(assets)} actif(s) — généré le {generated_at}", styles["Normal"]),
        Spacer(1, 8 * mm),
    ]

    header = ["Nom", "OS", "CPU", "Arch.", "Cœurs", "RAM", "Disques", "Apps"]
    rows = [header]
    for a in assets:
        hw = a.hardware or {}
        rows.append([
            Paragraph(a.name or "—", cell_style),
            Paragraph(" ".join(filter(None, [a.os, a.os_version])) or "—", cell_style),
            Paragraph(hw.get("cpu") or "—", cell_style),
            Paragraph(hw.get("arch") or "—", cell_style),
            str(hw.get("cores")) if hw.get("cores") is not None else "—",
            f"{hw['ram_gb']} Go" if hw.get("ram_gb") else "—",
            Paragraph(_format_disks(hw.get("disks")), cell_style),
            str(len(a.installed_packages or [])),
        ])

    summary = Table(rows, repeatRows=1, colWidths=[35 * mm, 32 * mm, 42 * mm, 16 * mm, 14 * mm, 16 * mm, 46 * mm, 14 * mm])
    summary.setStyle(_table_style())
    elements.append(summary)

    doc.build(elements)
    return buffer.getvalue()
