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
import threading
import time
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ASSETS_DIR = os.path.join(ROOT_DIR, "assets")
FONT_REGULAR = "/usr/share/fonts/truetype/jetbrains-mono-zorin-os/JetBrainsMono-Regular.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/jetbrains-mono-zorin-os/JetBrainsMono-Bold.ttf"

ANSI_COLOR_MAP = {
    30: "#0d1117",  # black
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
    97: "#ffffff",  # pure white
}

ANSI_BG_MAP = {
    40: "#000000",  # pure black bg (used by QR code & badges)
    41: "#b62324",
    42: "#2ea043",  # active green bg
    43: "#d29922",  # yellow/amber bg
    44: "#1f6feb",
    45: "#8957e5",
    46: "#39c5cf",  # cyan pill bg
    47: "#6e7681",
    100: "#30363d",
    107: "#ffffff",
}

DEFAULT_FG = "#c9d1d9"
DEFAULT_BG = "#0d1117"

SPARK_LEVELS = {
    "▁": 1 / 8,
    "▂": 2 / 8,
    "▃": 3 / 8,
    "▄": 4 / 8,
    "▅": 5 / 8,
    "▆": 6 / 8,
    "▇": 7 / 8,
}


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
vallum_datagrams_sent=184210
vallum_datagrams_failed=0
vallum_packets_delivered=341920
vallum_packets_failed=0
vallum_handshakes_established=14
vallum_handshakes_refused=0
vallum_reassembled=56
vallum_fragments_dropped=0
public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
vallum_public_line=vallum1:0003:4a8f9c2d1e0b5a37:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=

public_key=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
vallum_fingerprint=8b7e6d5c4b3a2918
vallum_public_line=vallum1:0003:8b7e6d5c4b3a2918:/v7+/f79/Pn49/b19PPz8vHx7+7t7Ovp6Ofm5eTj4uE=
vallum_name=gateway-us-east
allowed_ip=10.7.0.2/32
endpoint=198.51.100.10:51820
persistent_keepalive_interval=25
vallum_epoch=4
rx_bytes=142857120
tx_bytes=384910240
last_handshake_time_sec={now - 14}
last_handshake_time_nsec=0
preshared_key=true

public_key=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff
vallum_fingerprint=3f4e5d6c7b8a9012
vallum_public_line=vallum1:0003:3f4e5d6c7b8a9012:ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQCqu8zd7v8=
vallum_name=charlie-macbook
allowed_ip=10.7.0.3/32
endpoint=203.0.113.45:54321
persistent_keepalive_interval=25
vallum_epoch=2
rx_bytes=52840100
tx_bytes=18492000
last_handshake_time_sec={now - 42}
last_handshake_time_nsec=0
preshared_key=true

public_key=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
vallum_fingerprint=1a2b3c4d5e6f7081
vallum_public_line=vallum1:0003:1a2b3c4d5e6f7081:qrvM3e7/ESIzRFVmd4iZAKq7zN3u/xEiM0RVZneImQA=
vallum_name=dev-bastion-01
allowed_ip=10.7.0.10/32
endpoint=192.0.2.77:51820
vallum_epoch=1
rx_bytes=8940020
tx_bytes=14820100
last_handshake_time_sec={now - 1420}
last_handshake_time_nsec=0
preshared_key=false

public_key=3344556677889900112233445566778899001122334455667788990011223344
vallum_fingerprint=9e8d7c6b5a4f3021
vallum_public_line=vallum1:0003:9e8d7c6b5a4f3021:M0RVZneImQCqu8zd7v8RIjNEVWZ3iJkAqrvM3e7/ESIz
vallum_name=edge-node-frankfurt
allowed_ip=10.7.0.25/32
endpoint=[2a01:4f8::1]:51820
persistent_keepalive_interval=25
vallum_epoch=7
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
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                fg = DEFAULT_FG
                bg = None
                bold = False
            elif c == 1:
                bold = True
            elif c == 22:
                bold = False
            elif c == 38 and i + 4 < len(codes) and codes[i + 1] == 2:
                r, g, b = codes[i + 2], codes[i + 3], codes[i + 4]
                fg = f"#{r:02x}{g:02x}{b:02x}"
                i += 4
            elif c == 48 and i + 4 < len(codes) and codes[i + 1] == 2:
                r, g, b = codes[i + 2], codes[i + 3], codes[i + 4]
                bg = f"#{r:02x}{g:02x}{b:02x}"
                i += 4
            elif c in ANSI_COLOR_MAP:
                fg = ANSI_COLOR_MAP[c]
            elif c == 39:
                fg = DEFAULT_FG
            elif c in ANSI_BG_MAP:
                bg = ANSI_BG_MAP[c]
            elif c == 49:
                bg = None
            i += 1
        pos = match.end()
    return tokens


def draw_cell_glyph_or_primitive(draw, ch, x_pos, y_pos, cw, lh, fg, bg, t_font):
    x0 = int(round(x_pos))
    x1 = int(round(x_pos + cw))
    y0 = int(round(y_pos))
    y1 = int(round(y_pos + lh))
    ym = y0 + (y1 - y0) // 2
    xm = x0 + (x1 - x0) // 2

    if bg:
        draw.rectangle([(x0, y0), (x1, y1)], fill=bg)

    # Pixel-exact block characters (used by QR code, progress bars, cursor, sparklines)
    if ch == "█":
        draw.rectangle([(x0, y0), (x1, y1)], fill=fg)
        return
    if ch == "▀":
        draw.rectangle([(x0, y0), (x1, ym)], fill=fg)
        return
    if ch == "▄":
        draw.rectangle([(x0, ym), (x1, y1)], fill=fg)
        return
    if ch == "▌":
        draw.rectangle([(x0, y0), (xm, y1)], fill=fg)
        return
    if ch in SPARK_LEVELS:
        ratio = SPARK_LEVELS[ch]
        bar_h = max(2, int(round((y1 - y0) * ratio)))
        draw.rectangle([(x0, y1 - bar_h), (max(x0 + 1, x1 - 1), y1)], fill=fg)
        return

    # Seamless box-drawing primitives so borders connect without gaps
    if ch == "─":
        draw.line([(x0, ym), (x1, ym)], fill=fg, width=1)
        return
    if ch == "│":
        draw.line([(xm, y0), (xm, y1)], fill=fg, width=1)
        return
    if ch == "╭":
        draw.line([(xm, ym), (x1, ym)], fill=fg, width=1)
        draw.line([(xm, ym), (xm, y1)], fill=fg, width=1)
        return
    if ch == "╮":
        draw.line([(x0, ym), (xm, ym)], fill=fg, width=1)
        draw.line([(xm, ym), (xm, y1)], fill=fg, width=1)
        return
    if ch == "╰":
        draw.line([(xm, y0), (xm, ym)], fill=fg, width=1)
        draw.line([(xm, ym), (x1, ym)], fill=fg, width=1)
        return
    if ch == "╯":
        draw.line([(xm, y0), (xm, ym)], fill=fg, width=1)
        draw.line([(x0, ym), (xm, ym)], fill=fg, width=1)
        return

    if ch != " ":
        draw.text((x0, y0 + 1), ch, font=t_font, fill=fg)


def render_to_image(ansi_text, title="vallum tui — vallum0 (post-quantum tri-hybrid)"):
    lines = ansi_text.splitlines()
    num_lines = len(lines)
    max_cols = max((len(re.sub(r"\x1b\[[0-9;]*m", "", line)) for line in lines), default=120)

    char_w = 10
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
            for ch in text:
                draw_cell_glyph_or_primitive(
                    draw, ch, x_pos, y_pos, char_w, line_h, fg, bg, t_font
                )
                x_pos += char_w
        y_pos += line_h

    # Window outer border
    draw.rounded_rectangle([(0, 0), (img_w - 1, img_h - 1)], radius=8, outline="#30363d", width=1)

    return img


def render_to_svg(ansi_text, title="vallum tui — vallum0 (post-quantum tri-hybrid)"):
    lines = ansi_text.splitlines()
    num_lines = len(lines)
    max_cols = max((len(re.sub(r"\x1b\[[0-9;]*m", "", line)) for line in lines), default=120)

    char_w = 10
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
                ym = y_pos + line_h // 2
                xm = x_pos + cw // 2
                if bg:
                    svg_parts.append(
                        f'<rect x="{x_pos}" y="{y_pos}" width="{cw}" height="{line_h}" fill="{bg}"/>'
                    )
                if ch == "█":
                    svg_parts.append(
                        f'<rect x="{x_pos}" y="{y_pos}" width="{cw}" height="{line_h}" fill="{fg}"/>'
                    )
                elif ch == "▀":
                    svg_parts.append(
                        f'<rect x="{x_pos}" y="{y_pos}" width="{cw}" height="{line_h // 2}" fill="{fg}"/>'
                    )
                elif ch == "▄":
                    svg_parts.append(
                        f'<rect x="{x_pos}" y="{ym}" width="{cw}" height="{line_h // 2}" fill="{fg}"/>'
                    )
                elif ch == "▌":
                    svg_parts.append(
                        f'<rect x="{x_pos}" y="{y_pos}" width="{cw // 2}" height="{line_h}" fill="{fg}"/>'
                    )
                elif ch in SPARK_LEVELS:
                    bar_h = max(2, int(round(line_h * SPARK_LEVELS[ch])))
                    svg_parts.append(
                        f'<rect x="{x_pos}" y="{y_pos + line_h - bar_h}" width="{cw - 1}" height="{bar_h}" fill="{fg}"/>'
                    )
                elif ch == "─":
                    svg_parts.append(
                        f'<line x1="{x_pos}" y1="{ym}" x2="{x_pos + cw}" y2="{ym}" stroke="{fg}" stroke-width="1"/>'
                    )
                elif ch == "│":
                    svg_parts.append(
                        f'<line x1="{xm}" y1="{y_pos}" x2="{xm}" y2="{y_pos + line_h}" stroke="{fg}" stroke-width="1"/>'
                    )
                elif ch == "╭":
                    svg_parts.append(
                        f'<path d="M{xm},{y_pos + line_h} L{xm},{ym} L{x_pos + cw},{ym}" fill="none" stroke="{fg}" stroke-width="1"/>'
                    )
                elif ch == "╮":
                    svg_parts.append(
                        f'<path d="M{x_pos},{ym} L{xm},{ym} L{xm},{y_pos + line_h}" fill="none" stroke="{fg}" stroke-width="1"/>'
                    )
                elif ch == "╰":
                    svg_parts.append(
                        f'<path d="M{xm},{y_pos} L{xm},{ym} L{x_pos + cw},{ym}" fill="none" stroke="{fg}" stroke-width="1"/>'
                    )
                elif ch == "╯":
                    svg_parts.append(
                        f'<path d="M{x_pos},{ym} L{xm},{ym} L{xm},{y_pos}" fill="none" stroke="{fg}" stroke-width="1"/>'
                    )
                elif ch.strip():
                    escaped_ch = (
                        ch.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace('"', "&quot;")
                    )
                    svg_parts.append(
                        f'<text x="{x_pos}" y="{y_pos + 15}" fill="{fg}" font-weight="{weight}" class="base">{escaped_ch}</text>'
                    )
                x_pos += cw
        y_pos += line_h

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def generate_brandkit_board():
    """
    Generates a 3x3 premium Brand Identity System board (PNG) for VALLUM
    following the brandkit skill specification: dark charcoal canvas, clean
    presentation grid, strong gutters, geometric construction, and sparse
    high-hierarchy typography.
    """
    W, H = 1800, 1260
    GUTTER = 24
    MARGIN_X = 36
    MARGIN_TOP = 64
    MARGIN_BOT = 36

    grid_w = W - MARGIN_X * 2 - GUTTER * 2
    grid_h = H - MARGIN_TOP - MARGIN_BOT - GUTTER * 2
    cw = grid_w // 3
    ch = grid_h // 3

    img = Image.new("RGBA", (W, H), color="#07090d")
    draw = ImageDraw.Draw(img)

    f_hero = ImageFont.truetype(FONT_BOLD, 44)
    f_title = ImageFont.truetype(FONT_BOLD, 24)
    f_sub = ImageFont.truetype(FONT_BOLD, 16)
    f_body = ImageFont.truetype(FONT_REGULAR, 14)
    f_small = ImageFont.truetype(FONT_REGULAR, 12)
    f_label = ImageFont.truetype(FONT_BOLD, 11)

    # Top deck header bar
    draw.text((MARGIN_X, 22), "◆ VALLUM  //  BRAND & INTERFACE SYSTEM", font=f_sub, fill="#f0f6fc")
    draw.text(
        (W - MARGIN_X - 420, 24),
        "IKAROS DIGITAL × ATOMGUARD  ·  0x0003 TRI-HYBRID",
        font=f_small,
        fill="#6e7681",
    )

    def cell_rect(col, row):
        x0 = MARGIN_X + col * (cw + GUTTER)
        y0 = MARGIN_TOP + row * (ch + GUTTER)
        return x0, y0, x0 + cw, y0 + ch

    def draw_card(col, row, index_str, label_str, bg="#0d1117", border="#21262d"):
        x0, y0, x1, y1 = cell_rect(col, row)
        draw.rounded_rectangle([(x0, y0), (x1, y1)], radius=12, fill=bg, outline=border, width=1)
        draw.text((x0 + 22, y0 + 18), index_str, font=f_label, fill="#39c5cf")
        draw.text((x0 + 52, y0 + 18), label_str, font=f_label, fill="#6e7681")
        return x0, y0, x1, y1

    # 01 / LOGO COVER
    x0, y0, x1, y1 = draw_card(0, 0, "01", "PRIMARY WORDMARK & SEAL", bg="#0b0f16", border="#30363d")
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2 - 12
    # Boundary crossing line: ──●──◆──●──
    draw.line([(cx - 120, cy - 42), (cx + 120, cy - 42)], fill="#30363d", width=2)
    draw.ellipse([(cx - 70, cy - 48), (cx - 58, cy - 36)], fill="#39c5cf")
    draw.ellipse([(cx + 58, cy - 48), (cx + 70, cy - 36)], fill="#39c5cf")
    draw.polygon([(cx, cy - 54), (cx + 12, cy - 42), (cx, cy - 30), (cx - 12, cy - 42)], fill="#39c5cf")
    draw.text((cx - 115, cy - 12), "◆ VALLUM", font=f_hero, fill="#f0f6fc")
    draw.text((cx - 122, cy + 54), "EVERY BOUNDARY UNDER WATCH.", font=f_sub, fill="#39c5cf")
    draw.text((x0 + 22, y1 - 32), "L3 POST-QUANTUM TUNNEL", font=f_small, fill="#6e7681")

    # 02 / SYMBOL CONSTRUCTION
    x0, y0, x1, y1 = draw_card(1, 0, "02", "BOUNDARY GEOMETRY  (1:1 GRID)")
    gx0, gy0 = x0 + 40, y0 + 56
    gw, gh = cw - 80, ch - 96
    for step in range(0, gw + 1, 32):
        draw.line([(gx0 + step, gy0), (gx0 + step, gy0 + gh)], fill="#161b22", width=1)
    for step in range(0, gh + 1, 32):
        draw.line([(gx0, gy0 + step), (gx0 + gw, gy0 + step)], fill="#161b22", width=1)
    mcx, mcy = gx0 + gw // 2, gy0 + gh // 2
    draw.line([(gx0 + 24, mcy), (gx0 + gw - 24, mcy)], fill="#39c5cf", width=2)
    draw.line([(mcx, gy0 + 18), (mcx, gy0 + gh - 18)], fill="#30363d", width=1)
    draw.ellipse([(mcx - 110, mcy - 10), (mcx - 90, mcy + 10)], fill="#0d1117", outline="#39c5cf", width=3)
    draw.ellipse([(mcx + 90, mcy - 10), (mcx + 110, mcy + 10)], fill="#0d1117", outline="#39c5cf", width=3)
    draw.polygon([(mcx, mcy - 26), (mcx + 26, mcy), (mcx, mcy + 26), (mcx - 26, mcy)], fill="#161b22", outline="#39c5cf")
    draw.polygon([(mcx, mcy - 12), (mcx + 12, mcy), (mcx, mcy + 12), (mcx - 12, mcy)], fill="#39c5cf")
    draw.text((mcx - 135, mcy + 22), "INITIATOR", font=f_label, fill="#8b949e")
    draw.text((mcx - 42, mcy + 34), "RAMPART GATE", font=f_label, fill="#39c5cf")
    draw.text((mcx + 68, mcy + 22), "RESPONDER", font=f_label, fill="#8b949e")

    # 03 / DIGITAL COCKPIT SURFACE
    x0, y0, x1, y1 = draw_card(2, 0, "03", "COCKPIT TELEMETRY SURFACE")
    bx0, by0, bx1, by1 = x0 + 24, y0 + 54, x1 - 24, y1 - 24
    draw.rounded_rectangle([(bx0, by0), (bx1, by1)], radius=8, fill="#090d12", outline="#30363d", width=1)
    draw.text((bx0 + 14, by0 + 10), "◆ Vallum ❯ TUNNEL CONTROL", font=f_small, fill="#39c5cf")
    draw.rounded_rectangle([(bx0 + 14, by0 + 36), (bx0 + 108, by0 + 60)], radius=4, fill="#2ea043")
    draw.text((bx0 + 22, by0 + 40), "● ACTIVE", font=f_small, fill="#0d1117")
    draw.rounded_rectangle([(bx0 + 118, by0 + 36), (bx0 + 250, by0 + 60)], radius=4, fill="#39c5cf")
    draw.text((bx0 + 126, by0 + 40), "[1/1] vallum0", font=f_small, fill="#0d1117")
    draw.text((bx0 + 14, by0 + 72), "CONTROL LIVE · last reply 0s · systemd active", font=f_small, fill="#3fb950")
    draw.text((bx0 + 14, by0 + 96), "suite 0x0003 (tri-hybrid)   listen 0.0.0.0:51820", font=f_small, fill="#c9d1d9")
    # Mini sparkline bars
    samples = [5, 8, 12, 10, 16, 22, 19, 15, 24, 28, 25, 20, 26, 30, 27, 23, 29, 32, 26, 24, 28, 30]
    sx = bx0 + 14
    sy_base = by1 - 22
    draw.text((sx, sy_base - 52), "▼ RX 1.4 MB/s   ▲ TX 3.7 MB/s", font=f_small, fill="#39c5cf")
    for idx, val in enumerate(samples):
        bh = val
        draw.rectangle([(sx + idx * 18, sy_base - bh), (sx + idx * 18 + 13, sy_base)], fill="#39c5cf" if idx % 2 == 0 else "#bc8cff")

    # 04 / BRAND ESSENCE
    x0, y0, x1, y1 = draw_card(0, 1, "04", "BRAND POSTURE & VOICE")
    draw.text((x0 + 28, y0 + 64), "Calm authority.", font=f_title, fill="#f0f6fc")
    draw.text((x0 + 28, y0 + 100), "Honest telemetry.", font=f_title, fill="#39c5cf")
    draw.text((x0 + 28, y0 + 136), "Zero crypto lock-in.", font=f_title, fill="#8b949e")
    draw.line([(x0 + 28, y0 + 182), (x1 - 28, y0 + 182)], fill="#21262d", width=1)
    draw.text((x0 + 28, y0 + 200), "Built for network operators who need immediate", font=f_body, fill="#c9d1d9")
    draw.text((x0 + 28, y0 + 224), "answers: is the boundary up, is control live,", font=f_body, fill="#c9d1d9")
    draw.text((x0 + 28, y0 + 248), "and which peers have fresh handshakes.", font=f_body, fill="#c9d1d9")

    # 05 / SEMANTIC COLOR SYSTEM
    x0, y0, x1, y1 = draw_card(1, 1, "05", "SEMANTIC SIGNAL PALETTE")
    swatches = [
        ("#0D1117", "OBSIDIAN", "Canvas"),
        ("#39C5CF", "SIGNAL CYAN", "Focus / Nav"),
        ("#3FB950", "LIVE GREEN", "Healthy"),
        ("#D29922", "STALE AMBER", "Aging / Warn"),
        ("#FF7B72", "FAULT CORAL", "Unavailable"),
        ("#BC8CFF", "TX VIOLET", "Outbound"),
    ]
    sw_w = (cw - 64) // 3
    sw_h = 104
    for idx, (hex_c, name, role) in enumerate(swatches):
        sc = idx % 3
        sr = idx // 3
        sx0 = x0 + 22 + sc * (sw_w + 10)
        sy0 = y0 + 56 + sr * (sw_h + 14)
        draw.rounded_rectangle([(sx0, sy0), (sx0 + sw_w, sy0 + sw_h)], radius=8, fill="#161b22", outline="#30363d", width=1)
        draw.rounded_rectangle([(sx0 + 8, sy0 + 8), (sx0 + sw_w - 8, sy0 + 48)], radius=5, fill=hex_c, outline="#30363d", width=1)
        draw.text((sx0 + 10, sy0 + 56), name, font=f_label, fill="#f0f6fc")
        draw.text((sx0 + 10, sy0 + 74), f"{hex_c} · {role}", font=f_label, fill="#8b949e")

    # 06 / TYPOGRAPHY SPECIMEN
    x0, y0, x1, y1 = draw_card(2, 1, "06", "TYPOGRAPHY  ·  JETBRAINS MONO")
    draw.text((x0 + 26, y0 + 54), "Aa Bb 0123", font=f_hero, fill="#f0f6fc")
    draw.text((x0 + 26, y0 + 118), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", font=f_sub, fill="#39c5cf")
    draw.text((x0 + 26, y0 + 144), "0123456789  [2a01:4f8::1]:51820", font=f_body, fill="#c9d1d9")
    draw.line([(x0 + 26, y0 + 178), (x1 - 26, y0 + 178)], fill="#21262d", width=1)
    draw.text((x0 + 26, y0 + 194), "PUBLIC LINE IDENTITY FORMAT", font=f_label, fill="#6e7681")
    draw.text((x0 + 26, y0 + 216), "vallum1:0003:8b7e6d5c4b3a2918:...", font=f_body, fill="#3fb950")
    draw.text((x0 + 26, y0 + 244), "Tabular alignment · zero ambiguity", font=f_small, fill="#8b949e")

    # 07 / OPTICAL PROVISIONING (QR SEAL)
    x0, y0, x1, y1 = draw_card(0, 2, "07", "OPTICAL PROVISIONING  (ISO 18004)")
    # Draw crisp mini 21x21 QR pattern with 2-module white quiet zone
    qr_size = 21
    quiet = 2
    mod_px = 8
    plate_px = (qr_size + quiet * 2) * mod_px
    qx0 = x0 + 28
    qy0 = y0 + 58
    draw.rectangle([(qx0, qy0), (qx0 + plate_px, qy0 + plate_px)], fill="#ffffff")

    def draw_finder(fx, fy):
        for r in range(7):
            for c in range(7):
                if r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4):
                    px = qx0 + (quiet + fx + c) * mod_px
                    py = qy0 + (quiet + fy + r) * mod_px
                    draw.rectangle([(px, py), (px + mod_px, py + mod_px)], fill="#000000")

    draw_finder(0, 0)
    draw_finder(qr_size - 7, 0)
    draw_finder(0, qr_size - 7)
    for r in range(qr_size):
        for c in range(qr_size):
            in_tl = r < 8 and c < 8
            in_tr = r < 8 and c >= qr_size - 8
            in_bl = r >= qr_size - 8 and c < 8
            if not (in_tl or in_tr or in_bl):
                if (r == 6 or c == 6) and (r + c) % 2 == 0:
                    dark = True
                else:
                    dark = ((r * 17 + c * 31 + r * c) % 5) in (0, 2)
                if dark:
                    px = qx0 + (quiet + c) * mod_px
                    py = qy0 + (quiet + r) * mod_px
                    draw.rectangle([(px, py), (px + mod_px, py + mod_px)], fill="#000000")

    rx_info = qx0 + plate_px + 22
    draw.rounded_rectangle([(rx_info, qy0 + 4), (x1 - 24, qy0 + 30)], radius=4, fill="#39c5cf")
    draw.text((rx_info + 10, qy0 + 9), "● ONE-TIME INVITE (VEN2)", font=f_small, fill="#0d1117")
    draw.rounded_rectangle([(rx_info, qy0 + 40), (x1 - 24, qy0 + 66)], radius=4, fill="#2ea043")
    draw.text((rx_info + 10, qy0 + 45), "● ZERO PRIVATE KEYS", font=f_small, fill="#0d1117")
    draw.text((rx_info, qy0 + 84), "Half-block 1:1 square", font=f_body, fill="#f0f6fc")
    draw.text((rx_info, qy0 + 108), "modules + 2px quiet zone", font=f_body, fill="#f0f6fc")
    draw.text((rx_info, qy0 + 138), "expect afa1f7be2ef6", font=f_small, fill="#39c5cf")
    draw.text((rx_info, qy0 + 160), "frame 1/1 [████████]", font=f_small, fill="#3fb950")

    # 08 / TRI-HYBRID CRYPTO ARCHITECTURE
    x0, y0, x1, y1 = draw_card(1, 2, "08", "CRYPTOGRAPHIC BOUNDARY ARCHITECTURE")
    legs = [
        ("LEG 01 · CLASSICAL", "X25519 ECDH", "#c9d1d9"),
        ("LEG 02 · NTRU LATTICE", "sntrup761 KEM", "#39c5cf"),
        ("LEG 03 · NIST FIPS 203", "ML-KEM-768", "#3fb950"),
    ]
    for idx, (tag, alg, col_hex) in enumerate(legs):
        ly = y0 + 58 + idx * 54
        draw.rounded_rectangle([(x0 + 24, ly), (x0 + 310, ly + 42)], radius=6, fill="#161b22", outline="#30363d", width=1)
        draw.text((x0 + 36, ly + 6), tag, font=f_label, fill="#8b949e")
        draw.text((x0 + 36, ly + 22), alg, font=f_small, fill=col_hex)
        draw.line([(x0 + 310, ly + 21), (x0 + 356, y0 + 136)], fill="#39c5cf", width=2)

    draw.rounded_rectangle([(x0 + 356, y0 + 88), (x1 - 24, y0 + 184)], radius=8, fill="#0b161e", outline="#39c5cf", width=2)
    draw.text((x0 + 372, y0 + 102), "HKDF-SHA3-256", font=f_sub, fill="#39c5cf")
    draw.text((x0 + 372, y0 + 128), "CryptoSuite Trait", font=f_body, fill="#f0f6fc")
    draw.text((x0 + 372, y0 + 152), "0x0003 Tri-Hybrid", font=f_small, fill="#3fb950")
    draw.text((x0 + 24, y1 - 34), "MEX-bound static ops · mutual confirmation · eCK-PFS-PSK", font=f_small, fill="#8b949e")

    # 09 / UI COMPONENT SYSTEM
    x0, y0, x1, y1 = draw_card(2, 2, "09", "INTERACTION & COMPONENT SYSTEM")
    # Command palette pill
    draw.rounded_rectangle([(x0 + 24, y0 + 58), (x0 + 168, y0 + 86)], radius=5, fill="#39c5cf")
    draw.text((x0 + 34, y0 + 64), ": commands", font=f_sub, fill="#0d1117")
    draw.rounded_rectangle([(x0 + 182, y0 + 58), (x0 + 310, y0 + 86)], radius=5, fill="#2ea043")
    draw.text((x0 + 194, y0 + 64), "● ACTIVE", font=f_sub, fill="#0d1117")
    draw.rounded_rectangle([(x0 + 324, y0 + 58), (x1 - 24, y0 + 86)], radius=5, fill="#30363d")
    draw.text((x0 + 338, y0 + 64), "RECENT · 14s", font=f_sub, fill="#3fb950")

    # Palette row preview
    draw.rounded_rectangle([(x0 + 24, y0 + 104), (x1 - 24, y0 + 194)], radius=6, fill="#090d12", outline="#30363d", width=1)
    draw.text((x0 + 36, y0 + 114), ": add peer▌", font=f_body, fill="#39c5cf")
    draw.rounded_rectangle([(x0 + 32, y0 + 138), (x1 - 32, y0 + 162)], radius=4, fill="#39c5cf")
    draw.text((x0 + 40, y0 + 142), "▸ PEER    add peer…                               a", font=f_small, fill="#0d1117")
    draw.text((x0 + 40, y0 + 166), "  BUNDLE  export client bundle… (charlie)       b x", font=f_small, fill="#c9d1d9")

    # Toast bar preview
    draw.rounded_rectangle([(x0 + 24, y1 - 52), (x0 + 56, y1 - 26)], radius=4, fill="#d29922")
    draw.text((x0 + 34, y1 - 47), "▸", font=f_sub, fill="#0d1117")
    draw.text((x0 + 68, y1 - 46), "ping 10.7.0.3: reply in 18.2 ms", font=f_body, fill="#e3b341")

    brandkit_png = os.path.join(ASSETS_DIR, "vallum-brandkit.png")
    img.convert("RGB").save(brandkit_png)
    print(f"  Generated 3x3 Brandkit board -> {brandkit_png}")



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
        ("palette", "assets/vallum-palette.png", None, "vallum tui — Command Palette (':' Interactive Dispatch)"),
        ("ping", "assets/vallum-ping.png", None, "vallum tui — Peer Ping Connectivity Probe"),
        ("filter", "assets/vallum-filter.png", None, "vallum tui — Interactive PSK Filter"),
        ("logs", "assets/vallum-logs.png", "assets/vallum-logs.svg", "vallum tui — Semantic Journald Logs"),
        ("qr", "assets/vallum-qr.png", None, "vallum tui — Multi-Frame Client Bundle QR Export"),
        ("empty", "assets/vallum-empty.png", None, "vallum tui — Onboarding Enclave"),
    ]

    captured_images = []
    durations = [2000, 1500, 1800, 2200, 1800, 2500, 2200, 2000]

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

    generate_brandkit_board()

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
    for f in sorted(os.listdir(ASSETS_DIR)):
        fpath = os.path.join(ASSETS_DIR, f)
        size_kb = os.path.getsize(fpath) / 1024
        print(f"  {f:25s} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
