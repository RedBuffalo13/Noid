# -*- coding: utf-8 -*-
"""Generate the full Noid icon set (Windows/Linux/Android) from the banner mark."""
import pathlib
from PIL import Image, ImageDraw

ROOT = pathlib.Path("D:/spud-mess/noid")
ICONS = ROOT / "src-tauri/icons"
ARES = ROOT / "src-tauri/gen/android/app/src/main/res"

VIO = (139, 92, 246, 255)   # #8b5cf6
GRN = (16, 185, 129, 255)   # #10b981
DARK = (10, 10, 11, 255)    # #0a0a0b
SURF = (18, 18, 22, 255)    # #121216
LITE = (232, 232, 236, 255) # #e8e8ec

SS = 4  # supersample factor


def mark(size, bg=True, pad=0.12, ring=0.055):
    """Draw the Noid mark: gradient ring + ECG pulse."""
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if bg:
        r = s * 0.22
        d.rounded_rectangle([0, 0, s - 1, s - 1], radius=r, fill=DARK)
        d.rounded_rectangle([2 * SS, 2 * SS, s - 1 - 2 * SS, s - 1 - 2 * SS],
                            radius=r * 0.9, fill=SURF)
    cx = cy = s / 2
    R = s * (0.5 - pad)
    w = max(2, int(s * ring))
    d.arc([cx - R, cy - R, cx + R, cy + R], 90, 270, fill=VIO, width=w)   # left half
    d.arc([cx - R, cy - R, cx + R, cy + R], 270, 90, fill=GRN, width=w)   # right half
    # ECG pulse inside the ring, ~0.62 of ring diameter
    u = R * 0.62
    pts = [(cx - u, cy), (cx - u * 0.42, cy), (cx - u * 0.22, cy - u * 0.55),
           (cx + u * 0.05, cy + u * 0.55), (cx + u * 0.24, cy), (cx + u, cy)]
    d.line(pts, fill=LITE, width=w, joint="curve")
    for x, y in (pts[0], pts[-1]):
        rr = w * 0.7
        d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=LITE)
    return img.resize((size, size), Image.LANCZOS)


def save(img, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path)
    print(path.name, img.size)


# ---------- Desktop / generic ----------
for n, px in [("32x32.png", 32), ("128x128.png", 128),
              ("128x128@2x.png", 256), ("icon.png", 512)]:
    save(mark(px), ICONS / n)

# Windows Store tiles (use the same mark, no transparency issues)
for n, px in [("Square30x30Logo.png", 30), ("Square44x44Logo.png", 44),
              ("Square71x71Logo.png", 71), ("Square89x89Logo.png", 89),
              ("Square107x107Logo.png", 107), ("Square142x142Logo.png", 142),
              ("Square150x150Logo.png", 150), ("Square284x284Logo.png", 284),
              ("Square310x310Logo.png", 310), ("StoreLogo.png", 50)]:
    save(mark(px), ICONS / n)

# icon.ico — multi-resolution (16..256)
ico = mark(256)
ico.save(ICONS / "icon.ico", format="ICO",
         sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icon.ico written")
ico.save(ICONS / "icon4.ico", format="ICO",
         sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icon4.ico written")

# icon.icns (macOS) — Pillow writes icns
try:
    big = mark(1024)
    big.save(ICONS / "icon.icns", format="ICNS")
    print("icon.icns written")
except Exception as e:
    print("icns skipped:", e)

# ---------- Android mipmaps ----------
# ic_launcher.png: mdpi 48, hdpi 72, xhdpi 96, xxhdpi 144, xxxhdpi 192
# ic_launcher_foreground.png: 108dp -> mdpi 108 .. xxxhdpi 432
DEN = {"mipmap-mdpi": (48, 108), "mipmap-hdpi": (72, 162),
       "mipmap-xhdpi": (96, 216), "mipmap-xxhdpi": (144, 324),
       "mipmap-xxxhdpi": (192, 432)}
for d, (lp, fg) in DEN.items():
    base = ARES / d
    save(mark(lp), base / "ic_launcher.png")
    save(mark(lp), base / "ic_launcher_round.png")
    # adaptive-icon foreground: transparent bg, mark at ~66% safe zone
    save(mark(fg, bg=False, pad=0.2, ring=0.05), base / "ic_launcher_foreground.png")

print("done")
