"""
Reporter — JSON and PDF output generation.
Embeds profile images/avatars in PDF when found.
NEVER includes the API key in any output.
"""
import io
import gzip
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from userhunt.config import Config


class Reporter:
    def __init__(self, config: Config):
        self.config = config

    def generate_json(self, case: Any, path: Path) -> Path:
        """Generate JSON report. NEVER includes API key. Optionally gzip compressed."""
        data = case.to_dict()

        # Add metadata
        data["ai_meta"] = {
            "provider": self.config.ai.provider.value,
            "model": self.config.ai.model,
            "calls_made": self.config.ai.calls_made,
        }

        # Ensure API key is NEVER in output
        data.pop("api_key", None)
        data.pop("github_token", None)

        # Strip any nested api_key fields from hits
        for hit in data.get("hits", []):
            hit.pop("api_key", None)
            hit.pop("key", None)

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        json_bytes = json.dumps(data, indent=2, default=str).encode("utf-8")
        
        if self.config.hunt.compress_output:
            # Gzip compress — saves 60-80% disk space
            gzip_path = path.with_suffix(".json.gz")
            tmp_gz = gzip_path.with_suffix(".tmp")
            with gzip.open(tmp_gz, "wb") as f:
                f.write(json_bytes)
            tmp_gz.replace(gzip_path)
            # Also keep uncompressed for easy reading
            with open(tmp, "wb") as f:
                f.write(json_bytes)
            tmp.replace(path)
        else:
            with open(tmp, "wb") as f:
                f.write(json_bytes)
            tmp.replace(path)
        
        return path

    def generate_pdf(self, case: Any, path: Path) -> Path:
        """Generate PDF report with embedded profile images."""
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        styles = getSampleStyleSheet()
        story: list = []

        # Title
        title_style = ParagraphStyle(
            "TitleCustom",
            parent=styles["Heading1"],
            textColor=colors.HexColor("#00bcd4"),
            spaceAfter=12,
        )
        story.append(Paragraph("USERHUNT — OSINT REPORT", title_style))
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            f"<b>Date:</b> {Path(path).stem}", styles["Normal"]
        ))
        story.append(Spacer(1, 12))

        # ── Identifiers ──
        if case.usernames:
            story.append(Paragraph("<b>Usernames</b>", styles["Heading2"]))
            story.append(Paragraph(
                ", ".join(case.usernames[:50]), styles["Normal"]
            ))
            story.append(Spacer(1, 6))
        if case.emails:
            story.append(Paragraph("<b>Emails</b>", styles["Heading2"]))
            story.append(Paragraph(
                ", ".join(case.emails[:50]), styles["Normal"]
            ))
            story.append(Spacer(1, 6))
        if case.names:
            story.append(Paragraph("<b>Full Names</b>", styles["Heading2"]))
            story.append(Paragraph(
                ", ".join(case.names[:50]), styles["Normal"]
            ))
            story.append(Spacer(1, 6))

        # ── Profile images / avatars ──
        images_section = self._collect_profile_images(case)
        if images_section:
            story.append(Paragraph("<b>Profile Images</b>", styles["Heading2"]))
            for img_data in images_section[:6]:
                img_bytes = img_data.get("bytes")
                source = img_data.get("source", "")
                if img_bytes:
                    try:
                        img = RLImage(io.BytesIO(img_bytes), width=2 * inch, height=2 * inch)
                        story.append(img)
                        story.append(Paragraph(
                            f"<i>{source}</i>", styles["Normal"]
                        ))
                        story.append(Spacer(1, 8))
                    except Exception:
                        # If image fails, just note it
                        story.append(Paragraph(
                            f"<i>Image from {source} (could not embed)</i>",
                            styles["Normal"],
                        ))
                else:
                    url = img_data.get("url", "")
                    if url:
                        story.append(Paragraph(
                            f"<i>Profile image: {url} ({source})</i>",
                            styles["Normal"],
                        ))
                        story.append(Spacer(1, 4))

        # ── HIGH hits ──
        high = [h for h in case.hits if h.get("confidence") == "HIGH"]
        if high:
            story.append(Paragraph(
                f"<b>HIGH Confidence Hits ({len(high)})</b>", styles["Heading2"]
            ))
            data = [["Platform", "URL", "Display Name"]]
            for h in high[:100]:
                data.append([
                    h.get("platform", ""),
                    h.get("url", "")[:80],
                    h.get("display_name", "")[:60],
                ])
            t = Table(data, colWidths=[1.2 * inch, 3.5 * inch, 2 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00bcd4")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))

        # ── MEDIUM hits ──
        medium = [h for h in case.hits if h.get("confidence") == "MEDIUM"]
        if medium:
            story.append(Paragraph(
                f"<b>MEDIUM Confidence Hits ({len(medium)})</b>",
                styles["Heading2"],
            ))
            data = [["Platform", "URL", "Display Name"]]
            for h in medium[:100]:
                data.append([
                    h.get("platform", ""),
                    h.get("url", "")[:80],
                    h.get("display_name", "")[:60],
                ])
            t = Table(data, colWidths=[1.2 * inch, 3.5 * inch, 2 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ff9800")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))

        # ── Pivot chain ──
        pivots = case.pivot_log.as_list() if hasattr(case.pivot_log, "as_list") else list(case.pivot_log)
        if pivots:
            story.append(Paragraph(
                f"<b>Pivot Chain ({len(pivots)} entries)</b>",
                styles["Heading2"],
            ))
            for p in pivots[-20:]:
                src = p.get("source", "?")
                found = p.get("found", "?")
                action = p.get("action", "?")
                reason = p.get("reason", "?")
                by = p.get("by", "?")
                story.append(Paragraph(
                    f"<font color='#666666'>[{src}]</font> "
                    f"<b>{found}</b> → {action} ({reason}) <i>by {by}</i>",
                    styles["Normal"],
                ))
            story.append(Spacer(1, 12))

        # ── AI Profile ──
        if case.ai_profile:
            story.append(Paragraph("<b>AI Profile Summary</b>", styles["Heading2"]))
            # Split into paragraphs for better PDF layout
            for para in case.ai_profile[:4000].split("\n"):
                if para.strip():
                    story.append(Paragraph(para.strip(), styles["Normal"]))
            story.append(Spacer(1, 12))

        # ── LOW hits (noted, excluded from body) ──
        low = [h for h in case.hits if h.get("confidence") == "LOW"]
        if low:
            story.append(Paragraph(
                f"<b>LOW Confidence Hits ({len(low)}) — excluded from body</b>",
                styles["Heading2"],
            ))

        # ── Summary ──
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            f"<b>Total Hits:</b> {len(case.hits)} | "
            f"<b>Pivot Log:</b> {len(pivots)} | "
            f"<b>Round:</b> {case.round}",
            styles["Normal"],
        ))

        doc.build(story)
        return path

    def _collect_profile_images(self, case: Any) -> List[Dict[str, Any]]:
        """
        Collect avatar URLs and image bytes from profile evidence.
        Returns list of {url, bytes, source}.
        """
        images: List[Dict[str, Any]] = []
        seen_urls: set = set()

        # From hits with profile evidence
        for hit in case.hits[:200]:
            evidence = hit.get("profile_evidence", {})
            if not evidence:
                continue

            # Avatar URL
            avatar = evidence.get("avatar_url", "")
            if avatar and avatar not in seen_urls:
                seen_urls.add(avatar)
                img_bytes = self._fetch_image_bytes(avatar)
                images.append({
                    "url": avatar,
                    "bytes": img_bytes,
                    "source": hit.get("platform", "unknown"),
                })

            # Other images from evidence
            for img_url in evidence.get("images", [])[:3]:
                if img_url and img_url not in seen_urls:
                    seen_urls.add(img_url)
                    img_bytes = self._fetch_image_bytes(img_url)
                    images.append({
                        "url": img_url,
                        "bytes": img_bytes,
                        "source": hit.get("platform", "unknown"),
                    })

            if len(images) >= 6:
                break

        return images

    @staticmethod
    def _fetch_image_bytes(url: str) -> Optional[bytes]:
        """Fetch image bytes from URL. Returns None on failure."""
        try:
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if "image" in content_type or url.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
                    # Verify it's a valid image by trying to open it
                    from PIL import Image
                    img = Image.open(io.BytesIO(resp.content))
                    # Resize to reasonable dimensions
                    img.thumbnail((400, 400))
                    buf = io.BytesIO()
                    img.save(buf, format="PNG")
                    return buf.getvalue()
        except Exception:
            pass
        return None
