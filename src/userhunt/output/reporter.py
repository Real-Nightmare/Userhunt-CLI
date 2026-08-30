"""
Reporter — JSON and PDF output generation.
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from userhunt.config import Config


class Reporter:
    def __init__(self, config: Config):
        self.config = config

    def generate_json(self, case: Any, path: Path) -> Path:
        data = case.to_dict()
        ai_meta = {
            "provider": self.config.ai.provider.value,
            "model": self.config.ai.model,
            "calls_made": self.config.ai.calls_made,
        }
        data["ai_meta"] = ai_meta
        data.pop("github_token", None)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, default=str)
        tmp.replace(path)
        return path

    def generate_pdf(self, case: Any, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        title_style = ParagraphStyle(
            "TitleCustom",
            parent=styles["Heading1"],
            textColor=colors.HexColor("#00bcd4"),
            spaceAfter=12,
        )
        story.append(Paragraph("USERHUNT — OSINT REPORT", title_style))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Date:</b> {Path(path).stem}", styles["Normal"]))
        story.append(Spacer(1, 12))
        if case.usernames:
            story.append(Paragraph("<b>Usernames</b>", styles["Heading2"]))
            story.append(Paragraph(", ".join(case.usernames[:50]), styles["Normal"]))
            story.append(Spacer(1, 6))
        if case.emails:
            story.append(Paragraph("<b>Emails</b>", styles["Heading2"]))
            story.append(Paragraph(", ".join(case.emails[:50]), styles["Normal"]))
            story.append(Spacer(1, 6))
        high = [h for h in case.hits if h.get("confidence") == "HIGH"]
        medium = [h for h in case.hits if h.get("confidence") == "MEDIUM"]
        low = [h for h in case.hits if h.get("confidence") == "LOW"]
        if high:
            story.append(Paragraph(f"<b>HIGH Confidence Hits ({len(high)})</b>", styles["Heading2"]))
            data = [["Platform", "URL", "Display Name"]]
            for h in high[:100]:
                data.append([h.get("platform", ""), h.get("url", "")[:80], h.get("display_name", "")[:60]])
            t = Table(data, colWidths=[1.2 * inch, 3.5 * inch, 2 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00bcd4")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))
        if medium:
            story.append(Paragraph(f"<b>MEDIUM Confidence Hits ({len(medium)})</b>", styles["Heading2"]))
            data = [["Platform", "URL", "Display Name"]]
            for h in medium[:100]:
                data.append([h.get("platform", ""), h.get("url", "")[:80], h.get("display_name", "")[:60]])
            t = Table(data, colWidths=[1.2 * inch, 3.5 * inch, 2 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ff9800")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))
        if case.ai_profile:
            story.append(Paragraph("<b>AI Profile</b>", styles["Heading2"]))
            story.append(Paragraph(case.ai_profile[:4000], styles["Normal"]))
            story.append(Spacer(1, 12))
        if low:
            story.append(Paragraph(f"<b>LOW Confidence Hits ({len(low)}) — excluded from body</b>", styles["Heading2"]))
        story.append(Paragraph(f"<b>Total Hits:</b> {len(case.hits)} | <b>Pivot Log:</b> {len(case.pivot_log)}", styles["Normal"]))
        doc.build(story)
        return path
