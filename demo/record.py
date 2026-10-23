"""Build the self-contained demo page and record it to video + GIF. Fully automated, no live Microsoft calls.

    python demo/run_demo.py                 # 1. run the simulated scenario -> demo/transcript.json
    python demo/record.py                   # 2. -> demo/demo.html, docs/demo.mp4, docs/demo.gif

Needs: playwright (pip install playwright; the Chromium it bundles or PLAYWRIGHT_BROWSERS_PATH) and ffmpeg on PATH.
Without them, demo/demo.html alone is the self-running browser demo: open it in any browser.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO, DOCS = ROOT / "demo", ROOT / "docs"
W, H = 1280, 720


def build_html() -> Path:
    transcript = (DEMO / "transcript.json").read_text()
    html = (DEMO / "player.html").read_text().replace("__TRANSCRIPT__", transcript.replace("</", "<\\/"))
    out = DEMO / "demo.html"
    out.write_text(html)
    return out


def record(page_path: Path, speed: float = 1.0) -> Path:
    from playwright.sync_api import sync_playwright
    vid_dir = DEMO / "_video"
    shutil.rmtree(vid_dir, ignore_errors=True)
    with sync_playwright() as p:
        import os
        exe = os.environ.get("ENTRA_MCP_CHROMIUM")          # optional: path to an existing Chromium binary
        try:
            browser = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
        except Exception as e:                                # browser not installed for this playwright version
            msg = str(e).splitlines()[0]
            raise SystemExit(f"Chromium is not available to Playwright ({msg}).\n"
                             f"Run once:  python -m playwright install chromium\n"
                             f"or point ENTRA_MCP_CHROMIUM at a Chromium/Chrome binary. demo/demo.html is already built "
                             f"and plays on its own in any browser.") from None
        ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(vid_dir),
                                  record_video_size={"width": W, "height": H}, device_scale_factor=1)
        page = ctx.new_page()
        page.goto(f"file://{page_path}?speed={speed}")
        t0 = time.time()
        while time.time() - t0 < 400:
            if page.evaluate("document.body.dataset.done === '1'"):
                break
            time.sleep(0.5)
        time.sleep(1.5)
        video = page.video
        ctx.close()
        src = Path(video.path())
        browser.close()
    return src


def encode(src: Path) -> tuple[Path, Path]:
    DOCS.mkdir(exist_ok=True)
    mp4, gif = DOCS / "demo.mp4", DOCS / "demo.gif"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(src), "-c:v", "libx264", "-preset", "slow", "-crf", "26",
                    "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-an", str(mp4)], check=True)
    # GIF: 8 fps, 960 px wide, palette per scene; README-friendly size
    filters = "fps=8,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=96:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(src), "-vf", filters, str(gif)], check=True)
    return mp4, gif


def main() -> int:
    page = build_html()
    print(f"built {page.relative_to(ROOT)} ({page.stat().st_size // 1024} KB, self-contained)")
    try:
        import playwright  # noqa: F401
    except ImportError:
        print("playwright not installed: skipping video; open demo/demo.html in a browser for the self-running demo")
        return 0
    if not shutil.which("ffmpeg"):
        print("ffmpeg not on PATH: skipping video; open demo/demo.html in a browser for the self-running demo")
        return 0
    src = record(page)
    mp4, gif = encode(src)
    dur = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(mp4)],
                         capture_output=True, text=True).stdout.strip()
    shutil.rmtree(DEMO / "_video", ignore_errors=True)
    meta = {"mp4": str(mp4.relative_to(ROOT)), "mp4_bytes": mp4.stat().st_size, "gif": str(gif.relative_to(ROOT)),
            "gif_bytes": gif.stat().st_size, "duration_s": round(float(dur), 1), "resolution": f"{W}x{H}", "simulated": True}
    (DEMO / "recording.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
