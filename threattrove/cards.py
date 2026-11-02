"""Open Graph share cards: a 1200x630 PNG for one verdict.

A link to a lookup should unfurl into something worth clicking, and the
indicator on the card is always defanged, so a screenshot of the card can be
forwarded without handing anyone a live link.
"""

from __future__ import annotations

import collections
import io
import threading
from typing import Dict, Optional, Tuple

from .core import defang

try:                                   # Pillow is optional: the site works without it
    from PIL import Image, ImageDraw, ImageFont

    HAVE_PIL = True
except Exception:                      # noqa: BLE001 - any import failure means no cards
    Image = ImageDraw = ImageFont = None  # type: ignore[assignment]
    HAVE_PIL = False

WIDTH, HEIGHT = 1200, 630

BG = "#0b0f14"
PANEL = "#111823"
LINE = "#22303f"
TEXT = "#e3ecf5"
DIM = "#93a4b8"
MUTE = "#6b7d92"
ACCENT = "#38bdf8"

#: verdict -> (accent colour, pill text colour, tinted pill background)
VERDICT_STYLE: Dict[str, Tuple[str, str, str]] = {
    "malicious": ("#ef4444", "#ff6b6b", "#2a1416"),
    "suspicious": ("#f59e0b", "#fbbf24", "#2a2110"),
    "clean": ("#22c55e", "#4ade80", "#0f2318"),
    "known_good": ("#14b8a6", "#2dd4bf", "#0d2422"),
    "unknown": ("#7c8b9d", "#a7b4c4", "#1a222c"),
    "error": ("#7c8b9d", "#a7b4c4", "#1a222c"),
    "skipped": ("#7c8b9d", "#a7b4c4", "#1a222c"),
}

KIND_LABEL = {"hash": "FILE HASH", "url": "URL", "domain": "DOMAIN",
              "ip": "IP ADDRESS"}

_FONTS = {
    "mono": ("DejaVuSansMono.ttf", "LiberationMono-Regular.ttf",
             "DejaVuSansMono-Bold.ttf"),
    "bold": ("DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf",
             "DejaVuSans-Bold.ttf"),
    "sans": ("DejaVuSans.ttf", "LiberationSans-Regular.ttf",
             "DejaVuSans.ttf"),
}
_FONT_DIRS = (
    "/usr/share/fonts/truetype/dejavu/",
    "/usr/share/fonts/truetype/liberation/",
    "/usr/share/fonts/truetype/liberation2/",
    "/usr/share/fonts/dejavu/",
    "/usr/share/fonts/TTF/",
)

_font_cache: Dict[Tuple[str, int], object] = {}
_font_lock = threading.Lock()
_card_cache: "collections.OrderedDict[Tuple[str, ...], bytes]" = collections.OrderedDict()
_card_lock = threading.Lock()
_CACHE_MAX = 200


def available() -> bool:
    """True when cards can be rendered on this box."""
    return HAVE_PIL


def _font(name: str, size: int):
    key = (name, size)
    with _font_lock:
        if key in _font_cache:
            return _font_cache[key]
        font = None
        for fname in _FONTS.get(name, _FONTS["sans"]):
            for d in _FONT_DIRS:
                try:
                    font = ImageFont.truetype(d + fname, size)
                    break
                except Exception:      # noqa: BLE001 - keep looking
                    continue
            if font is not None:
                break
        if font is None:
            try:
                font = ImageFont.load_default(size=size)
            except Exception:          # noqa: BLE001 - very old Pillow
                font = ImageFont.load_default()
        _font_cache[key] = font
        return font


def _text_w(text: str, font) -> int:
    try:
        return int(font.getlength(text))
    except Exception:                  # noqa: BLE001
        return len(text) * 10


#: characters a line may break after. Dots and hyphens are deliberately not
#: here: breaking a hostname apart (``example[.]`` / ``com``) reads as a typo and
#: can split the ``[.]`` defang marker itself.
_BREAKS = ("/", "?", "&", " ", "_")


def _cut_index(text: str, font, max_w: int) -> int:
    """How much of ``text`` fits on one line, preferring a natural break.

    A URL cut mid-domain (``http://malware-delivery.exam`` / ``ple/payload``)
    reads as a typo, so the cut lands after a separator when one is close to
    the edge; otherwise it falls back to the widest plain cut.
    """
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _text_w(text[:mid], font) <= max_w:
            lo = mid
        else:
            hi = mid - 1
    fits = lo
    if fits >= len(text) or fits == 0:
        return max(fits, 1)
    window = text[:fits]
    for sep in _BREAKS:
        idx = window.rfind(sep)
        if idx > 0 and idx >= int(fits * 0.6):
            return idx + 1
    return fits


def _wrap(text: str, font, max_w: int, max_lines: int) -> list:
    """Wrap to at most ``max_lines`` lines; anything past that is truncated.

    The last line keeps the head and the tail of what is left
    (``https://cdn[.]bad…/setup[.]exe``) so the domain and the file extension
    both survive a long indicator.
    """
    if _text_w(text, font) <= max_w:
        return [text]
    lines, rest = [], text
    while rest:
        if len(lines) >= max_lines - 1:
            if _text_w(rest, font) <= max_w:      # it just fits; no ellipsis needed
                return lines + [rest]
            tail = rest[-20:]
            head = rest[:-len(tail)] if len(rest) > len(tail) else ""
            while head and _text_w(head + "…" + tail, font) > max_w:
                head = head[:-1]
            return lines + [(head + "…" + tail) if head else ("…" + tail)]
        cut = _cut_index(rest, font, max_w)
        lines.append(rest[:cut])
        rest = rest[cut:]
    return lines[:max_lines]


def _pill(draw, x: int, y: int, text: str, font, fg: str, bg: str) -> int:
    pad_x, pad_y = 18, 10
    w = _text_w(text, font) + pad_x * 2
    h = font.size + pad_y * 2 if hasattr(font, "size") else 44
    draw.rounded_rectangle([x, y, x + w, y + h], radius=h // 2, fill=bg)
    draw.text((x + pad_x, y + pad_y - 2), text, font=font, fill=fg)
    return w


def render(kind: str, value: str, verdict: str, score: Optional[int] = None,
           sources: int = 0) -> bytes:
    """Render (and cache) one card as PNG bytes."""
    if not HAVE_PIL:
        raise RuntimeError("Pillow is not installed")
    key = (kind, value, verdict, str(score), str(sources))
    with _card_lock:
        hit = _card_cache.get(key)
        if hit is not None:
            _card_cache.move_to_end(key)
            return hit

    accent, fg_pill, bg_pill = VERDICT_STYLE.get(verdict, VERDICT_STYLE["unknown"])
    label = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS",
             "clean": "CLEAN", "known_good": "KNOWN GOOD",
             "error": "ERROR", "skipped": "NOT CHECKED"}.get(verdict, "NO VERDICT")

    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    # panel + left accent bar
    draw.rectangle([0, 0, WIDTH - 1, HEIGHT - 1], fill=BG)
    draw.rectangle([40, 40, WIDTH - 40, HEIGHT - 40], fill=PANEL, outline=LINE)
    draw.rectangle([40, 40, 52, HEIGHT - 40], fill=accent)

    # brand
    brand = _font("bold", 30)
    draw.text((96, 84), "ThreatTrove", font=brand, fill=TEXT)
    draw.text((96 + _text_w("ThreatTrove", brand) + 14, 84), "·", font=brand, fill=MUTE)
    draw.text((96 + _text_w("ThreatTrove", brand) + 30, 90),
              KIND_LABEL.get(kind, kind.upper()), font=_font("sans", 24), fill=MUTE)

    # the indicator, defanged
    safe = defang(value)
    body_font = _font("mono", 54)
    lines = _wrap(safe, body_font, WIDTH - 220, 2)
    y = 210
    for line in lines:
        draw.text((96, y), line, font=body_font, fill=TEXT)
        y += 76

    # verdict pill + score
    pill_font = _font("bold", 28)
    w = _pill(draw, 96, y + 24, label, pill_font, fg_pill, bg_pill)
    detail = ""
    if score is not None and score > 0:
        # the score is a weighted sum, so a clean indicator scores below zero:
        # "score -40/100" on a forwarded image reads as a bug, so show it only
        # when something actually pushed the verdict up.
        detail = f"score {score}/100"
    if sources:
        detail = (detail + "  ·  " if detail else "") + f"{sources} source" + (
            "s" if sources != 1 else "")
    if detail:
        draw.text((96 + w + 22, y + 34), detail, font=_font("sans", 26), fill=DIM)

    # footer
    draw.line([96, HEIGHT - 110, WIDTH - 96, HEIGHT - 110], fill=LINE)
    draw.text((96, HEIGHT - 88), "threattrove.com", font=_font("sans", 26), fill=ACCENT)
    note = "one aggregated verdict instead of a wall of tabs"
    draw.text((WIDTH - 96 - _text_w(note, _font("sans", 22)), HEIGHT - 86), note,
              font=_font("sans", 22), fill=MUTE)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    data = buf.getvalue()

    with _card_lock:
        _card_cache[key] = data
        while len(_card_cache) > _CACHE_MAX:
            _card_cache.popitem(last=False)
    return data
