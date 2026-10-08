"""Render the demo as an MP4 screencast (no screen capture needed).

    uv run --with pillow --with imageio-ffmpeg python scripts/make_video.py
    -> media/memgate-demo.mp4  (1920x1080, 30 fps, H.264)

It runs the real demo (mock provider, defense off then on) through a recording
rich Console, then animates that output in a drawn terminal window with
captions. macOS fonts (Menlo, Helvetica, Apple Color Emoji) are assumed.
"""

from __future__ import annotations

import io
import os
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import imageio_ffmpeg  # noqa: E402
import numpy as np  # noqa: E402
from PIL import Image, ImageDraw, ImageFont  # noqa: E402
from rich.cells import cell_len  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.segment import Segment  # noqa: E402
from rich.style import Style  # noqa: E402
from rich.terminal_theme import TerminalTheme  # noqa: E402

import demo.run_demo as rd  # noqa: E402

W, H, FPS = 1920, 1080, 30
COLS = 110
REPO = "github.com/haqinam/agent-memgate"
OUT = ROOT / "media" / "memgate-demo.mp4"

THEME = TerminalTheme(
    (16, 18, 24), (225, 228, 235),
    [(30, 32, 40), (232, 84, 84), (80, 200, 120), (230, 190, 80), (90, 150, 240), (190, 120, 230),
     (80, 200, 220), (210, 210, 215)],
    [(110, 112, 120), (255, 110, 110), (110, 230, 150), (250, 215, 110), (120, 175, 255), (215, 150, 250),
     (120, 225, 240), (250, 250, 252)],
)
BG = (9, 11, 16)
WIN = (16, 18, 24)
FONT_DIR = Path("/System/Library/Fonts")
MONO = ImageFont.truetype(str(FONT_DIR / "Menlo.ttc"), 25, index=0)
MONO_B = ImageFont.truetype(str(FONT_DIR / "Menlo.ttc"), 25, index=1)
SANS = ImageFont.truetype(str(FONT_DIR / "HelveticaNeue.ttc"), 40, index=0)
SANS_B = ImageFont.truetype(str(FONT_DIR / "HelveticaNeue.ttc"), 40, index=1)
SANS_BIG = ImageFont.truetype(str(FONT_DIR / "HelveticaNeue.ttc"), 76, index=1)
SANS_SM = ImageFont.truetype(str(FONT_DIR / "HelveticaNeue.ttc"), 26, index=0)
EMOJI_FONT = ImageFont.truetype(str(FONT_DIR / "Apple Color Emoji.ttc"), 160)
EMOJI = set("👤🤖🔧☠🛡📤")

CW = MONO.getlength("M")
LH = 32
WX0, WY0, WX1, WY1 = 70, 36, W - 70, 912  # terminal window
TB = 44  # title bar height
PADX, PADY = 24, 14
ROWS = int((WY1 - WY0 - TB - 2 * PADY) // LH)


# ------------------------------------------------------------------ capture

def capture(defense: str) -> list[list[Segment]]:
    con = Console(record=True, width=COLS, file=io.StringIO(), force_terminal=True,
                  color_system="truecolor", highlight=False)
    rd.console = con
    rd.main(["--provider", "mock", "--defense", defense])
    segs = [s for s in con._record_buffer if not s.control]
    return [list(l) for l in Segment.split_lines(segs)]


def plain(line: list[Segment]) -> str:
    return "".join(s.text for s in line)


def crop(line: list[Segment], cells: int) -> list[Segment]:
    out, used = [], 0
    for s in line:
        n = cell_len(s.text)
        if used + n <= cells:
            out.append(s)
            used += n
        else:
            out.append(Segment(s.text[: max(0, cells - used)], s.style))
            break
    return out


# ------------------------------------------------------------------- render

@lru_cache(maxsize=None)
def emoji_img(ch: str, size: int) -> Image.Image:
    im = Image.new("RGBA", (200, 200), (0, 0, 0, 0))
    ImageDraw.Draw(im).text((0, 0), ch, font=EMOJI_FONT, embedded_color=True)
    im = im.crop(im.getbbox() or (0, 0, 1, 1))
    return im.resize((size, size), Image.LANCZOS)


def rgb(color, fg: bool):
    if color is None:
        return None
    return tuple(color.get_truecolor(THEME, foreground=fg))


def draw_line(img: Image.Image, d: ImageDraw.ImageDraw, x0: float, y: float, line: list[Segment]) -> None:
    x = x0
    for s in line:
        st: Style = s.style or Style()
        fg = rgb(st.color, True) or THEME.foreground_color
        bg = rgb(st.bgcolor, False)
        font = MONO_B if st.bold else MONO
        n = cell_len(s.text)
        if bg:
            d.rectangle([x, y - 2, x + n * CW, y + LH - 4], fill=bg)
        run = ""
        cx = x
        for ch in s.text:
            if ch in EMOJI:
                if run:
                    d.text((cx, y), run, font=font, fill=fg)
                    cx += len(run) * CW
                    run = ""
                e = emoji_img(ch, 26)
                img.paste(e, (int(cx), int(y + 1)), e)
                cx += cell_len(ch) * CW
            else:
                run += ch
        if run:
            d.text((cx, y), run, font=font, fill=fg)
        x += n * CW


def window(title: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([WX0 + 6, WY0 + 10, WX1 + 6, WY1 + 14], 18, fill=(4, 5, 8))  # shadow
    d.rounded_rectangle([WX0, WY0, WX1, WY1], 16, fill=WIN, outline=(48, 52, 62), width=2)
    d.rectangle([WX0 + 2, WY0 + TB, WX1 - 2, WY0 + TB + 1], fill=(40, 43, 52))
    for i, c in enumerate([(255, 95, 87), (254, 188, 46), (40, 200, 64)]):
        cx, cy = WX0 + 26 + i * 24, WY0 + TB // 2
        d.ellipse([cx - 7, cy - 7, cx + 7, cy + 7], fill=c)
    tw = SANS_SM.getlength(title)
    d.text(((W - tw) / 2, WY0 + 9), title, font=SANS_SM, fill=(150, 155, 165))
    return img, d


def caption_bar(d: ImageDraw.ImageDraw, caption: str, tag: str) -> None:
    if caption:
        bold = caption.startswith("!")
        text = caption.lstrip("!")
        f = SANS_B if bold else SANS
        tw = f.getlength(text)
        d.text(((W - tw) / 2, 942), text, font=f, fill=(255, 255, 255))
    d.text((WX0, H - 46), tag, font=SANS_SM, fill=(110, 115, 125))
    rw = SANS_SM.getlength(REPO)
    d.text((WX1 - rw, H - 46), REPO, font=SANS_SM, fill=(110, 115, 125))


def frame_terminal(lines: list[list[Segment]], caption: str, title: str, tag: str) -> np.ndarray:
    img, d = window(title)
    shown = lines[-ROWS:]
    y = WY0 + TB + PADY
    for ln in shown:
        draw_line(img, d, WX0 + PADX, y, ln)
        y += LH
    caption_bar(d, caption, tag)
    return np.asarray(img)


def frame_card(big: str, small: list[str]) -> np.ndarray:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    tw = SANS_BIG.getlength(big)
    y = H / 2 - 60 - 30 * len(small)
    d.text(((W - tw) / 2, y), big, font=SANS_BIG, fill=(255, 255, 255))
    y += 120
    for s in small:
        tw = SANS.getlength(s)
        d.text(((W - tw) / 2, y), s, font=SANS, fill=(170, 175, 185))
        y += 58
    rw = SANS_SM.getlength(REPO)
    d.text(((W - rw) / 2, H - 80), REPO, font=SANS_SM, fill=(110, 115, 125))
    return np.asarray(img)


# ----------------------------------------------------------------- timeline

CAPTIONS = {
    "off": [
        ("SESSION 1", "Session 1: normal use. The assistant reads the inbox."),
        ("SESSION 2", "Session 2: Alex asks for a wiki summary. The page hides an instruction."),
        ("POISONED MEMORY WRITTEN", "!The assistant saves the attacker's instruction to memory."),
        ("SESSION 3", "Session 3: a clean, ordinary request. No untrusted input."),
        ("OUTGOING EMAIL SENT", "!The email goes out with a hidden bcc to the attacker."),
    ],
    "on": [
        ("SESSION 1", "Same scripted model, same attack. memgate is on."),
        ("SESSION 2", "Session 2: the same poisoned wiki page."),
        ("MEMORY QUARANTINED", "!The boundary labels the note by its source: untrusted web content."),
        ("SESSION 3", "Session 3: the model still obeys the note and adds the bcc..."),
        ("STOPPED AT TOOL BOUNDARY", "!...and the send is stopped: the bcc came from the web page."),
    ],
}
HOLD_AFTER = {"POISONED MEMORY WRITTEN": 3.0, "OUTGOING EMAIL SENT": 3.2, "MEMORY QUARANTINED": 3.0,
              "STOPPED AT TOOL BOUNDARY": 3.6}


class Video:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.gen = imageio_ffmpeg.write_frames(
            str(path), (W, H), fps=FPS, codec="libx264", pix_fmt_out="yuv420p", macro_block_size=8,
            output_params=["-crf", "18", "-preset", "medium", "-movflags", "+faststart"])
        self.gen.send(None)
        self.frames = 0

    def put(self, frame: np.ndarray, seconds: float) -> None:
        b = np.ascontiguousarray(frame).tobytes()
        for _ in range(max(1, round(seconds * FPS))):
            self.gen.send(b)
            self.frames += 1

    def close(self) -> None:
        self.gen.close()


def play_run(v: Video, mode: str, lines: list[list[Segment]]) -> None:
    title = f"memgate demo  ·  defense {mode}"
    tag = "Scripted demo model: shows the mechanism, not a measured attack rate"
    cmd = f"$ uv run python demo/run_demo.py --provider mock --defense {mode}"
    prompt = Style(color="green", bold=True)
    screen: list[list[Segment]] = []
    caption = "No defense. An assistant with persistent memory." if mode == "off" else ""
    triggers = list(CAPTIONS[mode])

    # type the command
    for i in range(0, len(cmd) + 1, 2):
        v.put(frame_terminal(screen + [[Segment(cmd[:i] + "▌", prompt)]], caption, title, tag), 1 / FPS)
    screen.append([Segment(cmd, prompt)])
    v.put(frame_terminal(screen, caption, title, tag), 0.6)

    pending_hold = None
    for ln in lines:
        text = plain(ln)
        for key, cap in list(triggers):
            if key in text:
                caption = cap
                triggers.remove((key, cap))
                if key in HOLD_AFTER:
                    pending_hold = key
        if "👤 Alex:" in text:  # type the user's request
            total = cell_len(text)
            for n in range(0, total + 1, 3):
                v.put(frame_terminal(screen + [crop(ln, n)], caption, title, tag), 1 / FPS)
            screen.append(ln)
            v.put(frame_terminal(screen, caption, title, tag), 0.5)
            continue
        screen.append(ln)
        hold = 2 / FPS
        if "SESSION" in text and "─" in text:
            hold = 0.9
        if pending_hold and text.lstrip().startswith("╰"):
            hold = HOLD_AFTER[pending_hold]
            pending_hold = None
        if "RESULT:" in text:
            caption = "!RESULT: EXFILTRATED" if mode == "off" else "!RESULT: BLOCKED"
            hold = 3.0
        v.put(frame_terminal(screen, caption, title, tag), hold)


def main() -> int:
    os.environ.setdefault("MEMGATE_AUDIT_KEY", "demo")
    runs = {m: capture(m) for m in ("off", "on")}
    v = Video(OUT)
    v.put(frame_card("One web page. Three sessions. A silent bcc.",
                     ["How a single prompt injection becomes a standing instruction",
                      "in an AI assistant's memory, and how to stop it."]), 3.5)
    play_run(v, "off", runs["off"])
    v.put(frame_card("Now with memgate.",
                     ["Memory labelled by where it came from.",
                      "A flow policy checked at the tool boundary."]), 3.0)
    play_run(v, "on", runs["on"])
    v.put(frame_card("agent-memgate", ["Provenance-labelled agent memory + flow policy at the tool boundary.",
                                 "Open source, Apache-2.0. Reproduce it in one command."]), 4.0)
    v.close()
    print(f"wrote {OUT}  ({v.frames / FPS:.1f}s, {OUT.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
