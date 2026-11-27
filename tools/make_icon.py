"""Draws the ConWatch app icon and writes:
  crates/conwatch-app/assets/conwatch.ico   (multi-size, embedded into the .exe)
  crates/conwatch-app/assets/icon64.rgba    (raw 64x64 RGBA for the window and tray icons)
Requires Pillow.  Usage: python tools/make_icon.py
"""
import os
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'crates', 'conwatch-app', 'assets')
S = 1024


def draw():
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    # vertical gradient on a rounded square
    grad = Image.new('RGBA', (S, S))
    gp = grad.load()
    for y in range(S):
        t = y / (S - 1)
        c = (int(70 + (36 - 70) * t), int(138 + (88 - 138) * t), int(250 + (214 - 250) * t), 255)
        for x in range(S):
            gp[x, y] = c
    mask = Image.new('L', (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle((40, 40, S - 40, S - 40), radius=230, fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    # download arrow (amber), left; upload arrow (pink), right
    amber, pink = (253, 205, 54, 255), (255, 143, 183, 255)
    d.rectangle((250, 250, 350, 560), fill=amber)
    d.polygon([(160, 540), (440, 540), (300, 760)], fill=amber)
    d.rectangle((674, 460, 774, 770), fill=pink)
    d.polygon([(584, 480), (864, 480), (724, 260)], fill=pink)
    # soft base line
    d.rounded_rectangle((170, 820, 854, 850), radius=15, fill=(255, 255, 255, 150))
    return img


def main():
    os.makedirs(OUT, exist_ok=True)
    big = draw()
    sizes = [16, 24, 32, 48, 64, 128, 256]
    big.save(os.path.join(OUT, 'conwatch.ico'), format='ICO', sizes=[(s, s) for s in sizes])
    open(os.path.join(OUT, 'icon64.rgba'), 'wb').write(big.resize((64, 64), Image.LANCZOS).tobytes())
    big.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, 'preview.png'))
    print('written', os.listdir(OUT))


if __name__ == '__main__':
    main()
