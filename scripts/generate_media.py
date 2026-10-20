#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Generates high-fidelity screenshots, vector SVGs, animated GIF and MP4
media showcasing Vallum in operational dogfooding.
"""

import os
import re
import socket
import subprocess
import sys
import threading
import time
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ASSETS_DIR = os.path.join(ROOT_DIR, "assets")
FONT_REGULAR = "/usr/share/fonts/truetype/jetbrains-mono-zorin-os/JetBrainsMono-Regular.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/jetbrains-mono-zorin-os/JetBrainsMono-Bold.ttf"

ANSI_COLOR_MAP = {
    30: "#161b22",  # black
    31: "#ff7b72",  # red
    32: "#3fb950",  # green
    33: "#d29922",  # yellow
    34: "#58a6ff",  # blue
    35: "#bc8cff",  # magenta
    36: "#39c5cf",  # cyan
    37: "#c9d1d9",  # gray
    90: "#6e7681",  # dark gray
    91: "#ffa198",  # light red
    92: "#56d364",  # light green
    93: "#e3b341",  # light yellow
    94: "#79c0ff",  # light blue
    95: "#d2a8ff",  # light magenta
    96: "#56d4dd",  # light cyan
    97: "#f0f6fc",  # white
}

ANSI_BG_MAP = {
    40: "#161b22",
    41: "#b62324",
    42: "#238636",  # active green bg
    43: "#9e6a03",  # yellow bg
    44: "#1f6feb",
    45: "#8957e5",
    46: "#1b7c83",
    47: "#6e7681",
    100: "#30363d",
}

DEFAULT_FG = "#c9d1d9"
DEFAULT_BG = "#0d1117"


def run_mock_uapi_server(sock_path, stop_event):
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(5)
    server.settimeout(0.5)

    now = int(time.time())
    response = f"""vallum_interface=vallum0
vallum_listen=0.0.0.0:51820
listen_port=51820
fwmark=0
vallum_suite=0x0003
vallum_fingerprint=4a8f9c2d1e0b5a37
vallum_address=10.7.0.1/24
vallum_offload=true
vallum_batching=true
public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
vallum_public_line=vallum1:0003:4a8f9c2d1e0b5a37:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=

public_key=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
vallum_public_line=vallum1:0003:8b7e6d5c4b3a2918:/v7+/f79/Pn49/b19PPz8vHx7+7t7Ovp6Ofm5eTj4uE=
vallum_name=gateway-us-east
allowed_ip=10.7.0.2/32
endpoint=198.51.100.10:51820
rx_bytes=142857120
tx_bytes=384910240
last_handshake_time_sec={now - 14}
last_handshake_time_nsec=0
preshared_key=true

public_key=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff
vallum_public_line=vallum1:0003:3f4e5d6c7b8a9012:ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8=
vallum_name=charlie-macbook
allowed_ip=10.7.0.3/32
endpoint=203.0.113.45:54321
rx_bytes=52840100
tx_bytes=18492000
last_handshake_time_sec={now - 42}
last_handshake_time_nsec=0
preshared_key=true

public_key=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
vallum_public_line=vallum1:0003:1a2b3c4d5e6f7081:qrvM3e7/ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQA=
vallum_name=dev-bastion-01
allowed_ip=10.7.0.10/32
endpoint=192.0.2.77:51820
rx_bytes=8940020
tx_bytes=14820100
last_handshake_time_sec={now - 1420}
last_handshake_time_nsec=0
preshared_key=false

public_key=3344556677889900112233445566778899001122334455667788990011223344
vallum_public_line=vallum1:0003:9e8d7c6b5a4f3021:M0RVZneImQCqu8zd7v8RIjNEVWZ3iJkAqrvM3e7/ESIz
vallum_name=edge-node-frankfurt
allowed_ip=10.7.0.25/32
endpoint=[2a01:4f8::1]:51820
rx_bytes=89410300
tx_bytes=210150900
last_handshake_time_sec={now - 3}
last_handshake_time_nsec=0
preshared_key=true
errno=0
\n"""

    while not stop_event.is_set():
        try:
            conn, _ = server.accept()
            _ = conn.recv(1024)
            conn.sendall(response.encode("utf-8"))
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
    server.close()
    if os.path.exists(sock_path):
        os.unlink(sock_path)


def capture_snapshot(sock_path, view="dashboard", width=120, height=32):
    cmd = [
        "cargo",
        "run",
        "-q",
        "-p",
        "vallum",
        "--",
        "tui",
        "--control",
        sock_path,
        "--snapshot",
        "--ansi",
        "--width",
        str(width),
        "--height",
        str(height),
        "--snapshot-view",
        view,
    ]
    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, check=True)
    return res.stdout


def parse_ansi_line(line):
    tokens = []
    pattern = re.compile(r"\x1b\[([0-9;]*)m")
    pos = 0
    fg = DEFAULT_FG
    bg = None
    bold = False

    while pos < len(line):
        match = pattern.search(line, pos)
        if not match:
            text = line[pos:]
            if text:
                tokens.append((text, fg, bg, bold))
            break
        text = line[pos : match.start()]
        if text:
            tokens.append((text, fg, bg, bold))
        codes_str = match.group(1)
        codes = [int(c) for c in codes_str.split(";") if c] if codes_str else [0]
        for c in codes:
            if c == 0:
                fg = DEFAULT_FG
                bg = None
                bold = False
            elif c == 1:
                bold = True
            elif c == 22:
                bold = False
            elif c in ANSI_COLOR_MAP:
                fg = ANSI_COLOR_MAP[c]
            elif c == 39:
                fg = DEFAULT_FG
            elif c in ANSI_BG_MAP:
                bg = ANSI_BG_MAP[c]
            elif c == 49:
                bg = None
        pos = match.end()
    return tokens


def render_to_image(ansi_text, title="vallum tui — vallum0 (post-quantum tri-hybrid)"):
    lines = ansi_text.splitlines()
    num_lines = len(lines)
    max_cols = max((len(re.sub(r"\x1b\[[0-9;]*m", "", line)) for line in lines), default=120)

    char_w = 9.0
    line_h = 20
    pad_x = 24
    pad_top = 46
    pad_bot = 20

    img_w = int(max_cols * char_w + pad_x * 2)
    img_h = int(num_lines * line_h + pad_top + pad_bot)

    img = Image.new("RGBA", (img_w, img_h), color="#0d1117")
    draw = ImageDraw.Draw(img)

    # Window titlebar background
    draw.rectangle([(0, 0), (img_w, pad_top - 6)], fill="#161b22")
    draw.line([(0, pad_top - 6), (img_w, pad_top - 6)], fill="#30363d", width=1)

    # Window traffic lights
    dot_y = 20
    draw.ellipse([(18, dot_y - 6), (30, dot_y + 6)], fill="#ff5f56")
    draw.ellipse([(38, dot_y - 6), (50, dot_y + 6)], fill="#ffbd2e")
    draw.ellipse([(58, dot_y - 6), (70, dot_y + 6)], fill="#27c93f")

    # Title
    font_bold = ImageFont.truetype(FONT_BOLD, 14)
    font_reg = ImageFont.truetype(FONT_REGULAR, 14)

    title_bbox = font_bold.getbbox(title)
    title_w = title_bbox[2] - title_bbox[0]
    draw.text(((img_w - title_w) // 2, dot_y - 8), title, font=font_bold, fill="#8b949e")

    # Content
    font_content_reg = ImageFont.truetype(FONT_REGULAR, 15)
    font_content_bold = ImageFont.truetype(FONT_BOLD, 15)

    y_pos = pad_top
    for line in lines:
        tokens = parse_ansi_line(line)
        x_pos = pad_x
        for text, fg, bg, bold in tokens:
            t_font = font_content_bold if bold else font_content_reg
            # Render character by character to maintain strict grid alignment
            for ch in text:
                cw = char_w
                if bg:
                    draw.rectangle(
                        [(x_pos, y_pos), (x_pos + cw, y_pos + line_h)],
                        fill=bg,
                    )
                draw.text((x_pos, y_pos + 1), ch, font=t_font, fill=fg)
                x_pos += cw
        y_pos += line_h

    # Window outer border
    draw.rounded_rectangle([(0, 0), (img_w - 1, img_h - 1)], radius=8, outline="#30363d", width=1)

    return img


def render_to_svg(ansi_text, title="vallum tui — vallum0 (post-quantum tri-hybrid)"):
    lines = ansi_text.splitlines()
    num_lines = len(lines)
    max_cols = max((len(re.sub(r"\x1b\[[0-9;]*m", "", line)) for line in lines), default=120)

    char_w = 9.0
    line_h = 20
    pad_x = 24
    pad_top = 46
    pad_bot = 20

    img_w = int(max_cols * char_w + pad_x * 2)
    img_h = int(num_lines * line_h + pad_top + pad_bot)

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {img_w} {img_h}" width="{img_w}" height="{img_h}">',
        "<style>",
        "  .base { font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace; font-size: 15px; }",
        "  .title { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 13px; font-weight: 600; fill: #8b949e; }",
        "</style>",
        f'<rect width="{img_w}" height="{img_h}" rx="10" fill="#0d1117" stroke="#30363d" stroke-width="1"/>',
        f'<path d="M0,10 Q0,0 10,0 L{img_w-10},0 Q{img_w},0 {img_w},10 L{img_w},40 L0,40 Z" fill="#161b22"/>',
        f'<line x1="0" y1="40" x2="{img_w}" y2="40" stroke="#30363d" stroke-width="1"/>',
        '<circle cx="24" cy="20" r="6" fill="#ff5f56"/>',
        '<circle cx="44" cy="20" r="6" fill="#ffbd2e"/>',
        '<circle cx="64" cy="20" r="6" fill="#27c93f"/>',
        f'<text x="{img_w//2}" y="25" text-anchor="middle" class="title">{title}</text>',
    ]

    y_pos = pad_top
    for line in lines:
        tokens = parse_ansi_line(line)
        x_pos = pad_x
        for text, fg, bg, bold in tokens:
            weight = "bold" if bold else "normal"
            for ch in text:
                cw = char_w
                escaped_ch = (
                    ch.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
                )
                if bg:
                    svg_parts.append(
                        f'<rect x="{x_pos}" y="{y_pos}" width="{cw}" height="{line_h}" fill="{bg}"/>'
                    )
                if escaped_ch.strip():
                    svg_parts.append(
                        f'<text x="{x_pos}" y="{y_pos + 15}" fill="{fg}" font-weight="{weight}" class="base">{escaped_ch}</text>'
                    )
                x_pos += cw
        y_pos += line_h

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def main():
    os.makedirs(ASSETS_DIR, exist_ok=True)
    sock_path = "/tmp/vallum_media.sock"
    stop_event = threading.Event()
    server_thread = threading.Thread(target=run_mock_uapi_server, args=(sock_path, stop_event))
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.3)

    print("Capturing live operational frames from Vallum...")
    frames_spec = [
        ("dashboard", "assets/vallum-cockpit.png", "assets/vallum-cockpit.svg", "vallum tui — Cockpit Dashboard (Peer 1 Active)"),
        ("peer1", "assets/vallum-peer-macbook.png", None, "vallum tui — Selected Charlie's MacBook"),
        ("ping", "assets/vallum-ping.png", None, "vallum tui — Peer Ping Connectivity Probe"),
        ("filter", "assets/vallum-filter.png", None, "vallum tui — Interactive PSK Filter"),
        ("logs", "assets/vallum-logs.png", "assets/vallum-logs.svg", "vallum tui — Semantic Journald Logs"),
        ("qr", "assets/vallum-qr.png", None, "vallum tui — Multi-Frame Client Bundle QR Export"),
        ("empty", "assets/vallum-empty.png", None, "vallum tui — Onboarding Enclave"),
    ]

    captured_images = []
    durations = [2000, 1500, 2200, 1800, 2500, 2200, 2000]

    for view, png_rel, svg_rel, title in frames_spec:
        print(f"  Rendering view '{view}' -> {png_rel}")
        ansi_out = capture_snapshot(sock_path, view=view, width=120, height=32)

        # PNG
        img = render_to_image(ansi_out, title=title)
        png_path = os.path.join(ROOT_DIR, png_rel)
        img.save(png_path)
        captured_images.append(img.convert("RGB"))

        # SVG
        if svg_rel:
            svg_content = render_to_svg(ansi_out, title=title)
            svg_path = os.path.join(ROOT_DIR, svg_rel)
            with open(svg_path, "w", encoding="utf-8") as f:
                f.write(svg_content)

    stop_event.set()

    # Generate Animated GIF
    gif_path = os.path.join(ASSETS_DIR, "vallum-demo.gif")
    print(f"Generating animated GIF demo -> {gif_path}")
    captured_images[0].save(
        gif_path,
        save_all=True,
        append_images=captured_images[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )

    # Generate MP4 Video via ffmpeg
    mp4_path = os.path.join(ASSETS_DIR, "vallum-demo.mp4")
    print(f"Generating MP4 video capture via ffmpeg -> {mp4_path}")
    temp_dir = "/tmp/vallum_mp4_frames"
    os.makedirs(temp_dir, exist_ok=True)

    # Duplicate frames according to duration (at 10 fps)
    frame_idx = 0
    fps = 10
    for img, dur_ms in zip(captured_images, durations):
        repeat = int((dur_ms / 1000.0) * fps)
        for _ in range(repeat):
            f_path = os.path.join(temp_dir, f"frame_{frame_idx:04d}.png")
            img.save(f_path)
            frame_idx += 1

    ffmpeg_cmd = [
        "ffmpeg",
        "-y",
        "-framerate",
        str(fps),
        "-i",
        os.path.join(temp_dir, "frame_%04d.png"),
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-movflags",
        "+faststart",
        "-crf",
        "18",
        mp4_path,
    ]
    subprocess.run(ffmpeg_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("Media asset generation complete:")
    for f in os.listdir(ASSETS_DIR):
        fpath = os.path.join(ASSETS_DIR, f)
        size_kb = os.path.getsize(fpath) / 1024
        print(f"  {f:25s} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
