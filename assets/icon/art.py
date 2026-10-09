"""Fortix "Portal" app icon generator.

A white porcelain arch stands on a tile; through its opening a tunnel of lit
ribs recedes to a mint-white light, with a glowing lane along the floor.

All artwork is drawn in "art space": the 1024 icon canvas where the tile
occupies 100..924 (the macOS icon grid). Output modes re-map that space:

  background  full 1024 square, tile colour only (layer for the asset compiler)
  foreground  arch, tunnel, lane, glows and cast shadow on transparent (layer)
  square      background + foreground, edge to edge, unmasked
  icon        superellipse tile with drop shadow, art untransformed

Layer and square modes scale art space by 1024/824 so the tile fills the
canvas; the icon mode masks the same art with the superellipse, so a
composite of the layers equals the full icon up to that scale and mask.

Usage: art.py MODE THEME [small]
  MODE   background | foreground | square | icon
  THEME  light | dark (both render the graphite artwork)
  small  use the simplified master for 32 and 16 px renders
"""
import math
import sys

TILE_C, TILE_A, TILE_N = 512.0, 412.0, 4.6
LAYER_T = f"scale({1024/824:.6f}) translate(-100 -100)"


def squircle(cx, a, n):
    """Return an SVG path for a superellipse of half-size `a` centred at (cx, cx).

    The exponent `n` controls corner continuity; 4.6 approximates the macOS
    continuous-corner tile closely enough at icon sizes.
    """
    pts = []
    for i in range(720):
        t = 2 * math.pi * i / 720
        c, s = math.cos(t), math.sin(t)
        x = cx + a * math.copysign(abs(c) ** (2 / n), c)
        y = cx + a * math.copysign(abs(s) ** (2 / n), s)
        pts.append(f"{x:.2f},{y:.2f}")
    return "M" + " L".join(pts) + " Z"


def arch(cx, spring, r, bottom, closed=True):
    """Arch outline: straight legs from `bottom` to the springline, half circle on top.

    With `closed=False` the bottom edge is omitted so strokes do not draw a
    line across the threshold.
    """
    d = (f"M{cx-r:.1f} {bottom:.1f} L{cx-r:.1f} {spring:.1f} "
         f"A{r:.1f} {r:.1f} 0 0 1 {cx+r:.1f} {spring:.1f} L{cx+r:.1f} {bottom:.1f}")
    return d + (" Z" if closed else "")


def portal(g, dx=0.0, dy=0.0):
    """Outer portal silhouette with rounded feet, offset by (dx, dy) for extrusion."""
    r, k = g["R"], g["feet"]
    L, R = g["cx"] - r + dx, g["cx"] + r + dx
    sp, b = g["spring"] + dy, g["bottom"] + dy
    return (f"M{L+k:.1f} {b:.1f} Q{L:.1f} {b:.1f} {L:.1f} {b-k:.1f} L{L:.1f} {sp:.1f} "
            f"A{r} {r} 0 0 1 {R:.1f} {sp:.1f} L{R:.1f} {b-k:.1f} Q{R:.1f} {b:.1f} {R-k:.1f} {b:.1f} Z")


def scaled(g, s):
    """Opening arch scaled about the vanishing point by perspective step `s` (0..1)."""
    vx, vy = g["V"]
    cx = vx + (g["cx"] - vx) * s
    sp = vy + (g["spring"] - vy) * s
    b = vy + (g["bottom"] - vy) * s
    return cx, sp, g["r"] * s, b


# Geometry. FULL is the detailed master (64 px and up); SMALL is the
# simplified master: a thicker ring, a larger light and no ribs, so that the
# arch and its light survive at 32 and 16 px.
FULL = dict(cx=512, spring=470, R=268, r=188, bottom=814, feet=30, V=(512, 502),
            ribs=[0.74, 0.55, 0.41, 0.305], end=0.225, ext=22, lane=34)
SMALL = dict(cx=512, spring=500, R=300, r=150, bottom=834, feet=40, V=(512, 560),
             ribs=[], end=0.38, ext=18, lane=46)

# Palette. The graphite tile is lit mainly by the tunnel: cool porcelain,
# mint-tinted reveal and rim, a deep shadow and a mint spill on the tile in
# front of the arch. Both appearances use it, so the icon is the same in light
# and dark mode.
THEMES = {
    "dark": dict(
        tile=[("0", "#383B47"), ("0.5", "#1E2029"), ("1", "#0E0F16")],
        sheen=("#C8D2E8", 0.16),
        face=[("0", "#FFFFFF"), ("0.5", "#F1F3F6"), ("1", "#D9DEE5")],
        faceShade="#2A3A55", faceShadeOp=0.14,
        side=[("0", "#D6DCE5"), ("1", "#99A2B1")],
        reveal=[("0", "#F2FBF9"), ("0.5", "#CFE6E4"), ("1", "#A3C3C4")],
        shadow="#000000", shadowOp=0.62, contact="#000000", contactOp=0.55,
        innerRim="#D9FFF5", innerRimOp=0.95, spill=0.6, sill="#C9FFF3", sillOp=0.85, edgeGlow=0.28, revealShadeOp=0.16,
        tileShadow="#000000", tileShadowOp=0.55, rim=("#FFFFFF", 0.14),
    ),
}
THEMES["light"] = THEMES["dark"]


def stops(lst, op=None):
    """Render gradient stops; `op` optionally sets one stop-opacity for all."""
    o = f' stop-opacity="{op}"' if op is not None else ""
    return "".join(f'<stop offset="{a}" stop-color="{c}"{o}/>' for a, c in lst)


def defs(t, g):
    """Shared <defs>: blur filters, tile, porcelain and tunnel gradients."""
    ecx, esp, er, eb = scaled(g, g["end"])
    top = g["spring"] - g["R"]
    return f'''<defs>
  <filter id="b4" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="4"/></filter>
  <filter id="b10" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="10"/></filter>
  <filter id="b24" x="-30%" y="-30%" width="160%" height="170%"><feGaussianBlur stdDeviation="24"/></filter>
  <filter id="b40" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="40"/></filter>
  <clipPath id="open"><path d="{arch(g['cx'], g['spring'], g['r'], g['bottom'])}"/></clipPath>
  <linearGradient id="tile" x1="0" y1="100" x2="0" y2="924" gradientUnits="userSpaceOnUse">{stops(t['tile'])}</linearGradient>
  <radialGradient id="tileHi" cx="300" cy="170" r="580" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="{t['sheen'][0]}" stop-opacity="{t['sheen'][1]}"/><stop offset="1" stop-color="{t['sheen'][0]}" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="face" x1="0" y1="{top}" x2="0" y2="{g['bottom']}" gradientUnits="userSpaceOnUse">{stops(t['face'])}</linearGradient>
  <linearGradient id="faceShade" x1="{g['cx']-g['R']}" y1="0" x2="{g['cx']+g['R']}" y2="0" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="{t['faceShade']}" stop-opacity="0"/><stop offset="0.55" stop-color="{t['faceShade']}" stop-opacity="0"/>
    <stop offset="1" stop-color="{t['faceShade']}" stop-opacity="{t['faceShadeOp']}"/>
  </linearGradient>
  <linearGradient id="faceRim" x1="0" y1="{top}" x2="0" y2="{g['bottom']}" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="#FFFFFF" stop-opacity="1"/><stop offset="0.5" stop-color="#FFFFFF" stop-opacity="0.55"/><stop offset="1" stop-color="#FFFFFF" stop-opacity="0.15"/>
  </linearGradient>
  <radialGradient id="spec" cx="{g['cx']-g['R']*0.55:.0f}" cy="{top+g['R']*0.32:.0f}" r="{g['R']*0.75:.0f}" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="#FFFFFF" stop-opacity="0.9"/><stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="side" x1="0" y1="{top}" x2="0" y2="{g['bottom']+g['ext']}" gradientUnits="userSpaceOnUse">{stops(t['side'])}</linearGradient>
  <linearGradient id="reveal" x1="0" y1="{g['spring']-g['r']}" x2="0" y2="{g['bottom']}" gradientUnits="userSpaceOnUse">{stops(t['reveal'])}</linearGradient>
  <linearGradient id="revealShade" x1="{g['cx']-g['r']}" y1="0" x2="{g['cx']+g['r']}" y2="0" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="#FFFFFF" stop-opacity="0.35"/><stop offset="0.5" stop-color="#FFFFFF" stop-opacity="0"/>
    <stop offset="1" stop-color="#0A1030" stop-opacity="{t['revealShadeOp']}"/>
  </linearGradient>
  <linearGradient id="inside" x1="0" y1="{g['spring']-g['r']}" x2="0" y2="{g['bottom']}" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="#1C2360"/><stop offset="1" stop-color="#0B0F2E"/>
  </linearGradient>
  <linearGradient id="floor" x1="0" y1="{eb:.0f}" x2="0" y2="{g['bottom']}" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="#58A2D6"/><stop offset="0.4" stop-color="#2D4296"/><stop offset="1" stop-color="#161C4C"/>
  </linearGradient>
  <linearGradient id="lane" x1="0" y1="{eb:.0f}" x2="0" y2="{g['bottom']}" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="#EFFFFA"/><stop offset="0.35" stop-color="#5FF2D6"/><stop offset="1" stop-color="#2F8DFF"/>
  </linearGradient>
  <radialGradient id="light" cx="0.5" cy="0.62" r="0.62">
    <stop offset="0" stop-color="#FFFFFF"/><stop offset="0.5" stop-color="#DDFFF7"/><stop offset="1" stop-color="#74F2DD"/>
  </radialGradient>
  <clipPath id="ringClip"><path d="{portal(g)} {arch(g['cx'], g['spring'], g['r'], g['bottom'])}" clip-rule="evenodd"/></clipPath>
  <linearGradient id="sill" x1="{g['cx']-g['r']}" y1="0" x2="{g['cx']+g['r']+g['ext']*0.6}" y2="0" gradientUnits="userSpaceOnUse">
    <stop offset="0.3" stop-color="{t['sill']}" stop-opacity="0"/><stop offset="0.5" stop-color="{t['sill']}" stop-opacity="1"/><stop offset="0.7" stop-color="{t['sill']}" stop-opacity="0"/>
  </linearGradient>
  <radialGradient id="spillG" cx="0.5" cy="0.5" r="0.5">
    <stop offset="0" stop-color="#7FF5DF" stop-opacity="0.55"/><stop offset="1" stop-color="#7FF5DF" stop-opacity="0"/>
  </radialGradient>
</defs>'''


def background(t):
    """Tile colour: base gradient plus a soft top-left sheen, covering the whole tile."""
    return ('<rect x="96" y="96" width="832" height="832" fill="url(#tile)"/>'
            '<rect x="96" y="96" width="832" height="832" fill="url(#tileHi)"/>')


def foreground(t, g, small):
    """Arch, tunnel, lane, glows, and the soft shadow the arch casts on the tile."""
    ecx, esp, er, eb = scaled(g, g["end"])
    cx, sp, R, r, b = g["cx"], g["spring"], g["R"], g["r"], g["bottom"]
    opening = arch(cx, sp, r, b)
    out = []
    # Cast shadow on the tile, then a tighter contact shadow under the feet.
    out.append(f'<path d="{portal(g, 10, 44)}" fill="{t["shadow"]}" opacity="{t["shadowOp"]}" filter="url(#b24)"/>')
    out.append(f'<ellipse cx="{cx+10}" cy="{b+g["ext"]+6}" rx="{R+30}" ry="24" fill="{t["contact"]}" '
               f'opacity="{t["contactOp"]}" filter="url(#b10)"/>')
    # Dark theme: the tunnel light spills onto the tile in front of the arch.
    if t["spill"]:
        out.append(f'<ellipse cx="{cx+6}" cy="{b+g["ext"]+8}" rx="{r*0.95:.0f}" ry="30" fill="url(#spillG)" opacity="{t["spill"]}"/>')
    # Extrusion: the portal swept down-right in 1 px steps for a smooth side.
    ext = g["ext"]
    out.append("".join(f'<path d="{portal(g, i*0.6, i)}" fill="url(#side)"/>' for i in range(ext, 0, -1)))
    # Sill: the strip of extrusion below the opening catches the lane's light.
    out.append(f'<path d="M{cx-r} {b} L{cx+r} {b} L{cx+r+ext*0.6:.1f} {b+ext} L{cx-r+ext*0.6:.1f} {b+ext} Z" '
               f'fill="url(#sill)" opacity="{t["sillOp"]}"/>')
    # Porcelain face: a ring (outer silhouette minus opening, even-odd).
    ring = f'{portal(g)} {opening}'
    out.append(f'<path d="{ring}" fill="url(#face)" fill-rule="evenodd"/>')
    out.append(f'<path d="{ring}" fill="url(#faceShade)" fill-rule="evenodd"/>')
    if not small:
        out.append(f'<path d="{ring}" fill="url(#spec)" fill-rule="evenodd"/>')
    # Dark theme: the porcelain around the opening picks up the tunnel's mint light.
    if t["edgeGlow"]:
        out.append(f'<g clip-path="url(#ringClip)"><path d="{arch(cx, sp, r, b+40, closed=False)}" fill="none" '
                   f'stroke="#9CF7E6" stroke-opacity="{t["edgeGlow"]}" stroke-width="{26 if not small else 30}" filter="url(#b10)"/></g>')
    # Tunnel interior, clipped to the opening.
    tun = [f'<path d="{opening}" fill="url(#inside)"/>',
           f'<ellipse cx="{ecx:.1f}" cy="{esp:.1f}" rx="{r*1.2:.0f}" ry="{r*1.6:.0f}" fill="#2C74AE" opacity="0.55" filter="url(#b40)"/>',
           f'<path d="M{cx-r} {b} L{ecx-er:.1f} {eb:.1f} L{ecx+er:.1f} {eb:.1f} L{cx+r} {b} Z" fill="url(#floor)"/>']
    cols = ["#83AAFF", "#6FCBF6", "#64E4E1", "#8DF6E5"]
    for i, s in enumerate(g["ribs"], 1):
        rx, rsp, rr, rb = scaled(g, s)
        d = arch(rx, rsp, rr, rb, closed=False)
        tun.append(f'<path d="{d}" fill="none" stroke="#090C26" stroke-opacity="0.55" stroke-width="{22*s:.1f}"/>')
        tun.append(f'<path d="{d}" transform="translate(0 {-5*s:.1f})" fill="none" stroke="{cols[i-1]}" '
                   f'stroke-opacity="{0.40+0.12*i:.2f}" stroke-width="{7*s:.1f}" stroke-linecap="round"/>')
    tun.append(f'<circle cx="{ecx:.1f}" cy="{esp+er*0.4:.1f}" r="{er*2.9:.1f}" fill="#5FF2D6" opacity="0.5" filter="url(#b40)"/>')
    tun.append(f'<path d="{arch(ecx, esp, er, eb)}" fill="url(#light)"/>')
    lw = g["lane"]
    tun.append(f'<path d="M{cx-lw} {b} L{ecx-er*0.2:.1f} {eb:.1f} L{ecx+er*0.2:.1f} {eb:.1f} L{cx+lw} {b} Z" fill="url(#lane)"/>')
    if not small:
        tun.append(f'<path d="M{cx-lw} {b} L{ecx-er*0.2:.1f} {eb:.1f} L{ecx+er*0.2:.1f} {eb:.1f} L{cx+lw} {b} Z" '
                   f'fill="#7FF5DF" opacity="0.35" filter="url(#b10)"/>')
    # Reveal: the thickness of the opening, lit from the upper left, no bottom edge.
    rv = arch(cx, sp, r, b + 40, closed=False)
    rw = 40 if not small else 22
    tun.append(f'<path d="{rv}" fill="none" stroke="url(#reveal)" stroke-width="{rw}"/>')
    tun.append(f'<path d="{rv}" fill="none" stroke="url(#revealShade)" stroke-width="{rw}"/>')
    if not small:
        tun.append(f'<path d="{arch(cx, sp, r-20, b+40, closed=False)}" fill="none" stroke="#05071A" '
                   f'stroke-opacity="0.45" stroke-width="12" filter="url(#b10)" transform="translate(0 4)"/>')
    out.append(f'<g clip-path="url(#open)">{"".join(tun)}</g>')
    # Rim highlights on the face edges (skipped in the small master).
    if not small:
        out.append(f'<path d="{portal(g)}" fill="none" stroke="url(#faceRim)" stroke-width="4"/>')
        out.append(f'<path d="{arch(cx, sp, r, b, closed=False)}" fill="none" stroke="{t["innerRim"]}" '
                   f'stroke-opacity="{t["innerRimOp"]}" stroke-width="3"/>')
    return "".join(out)


def svg(body, d=""):
    """Wrap a body in a 1024 square SVG document."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">'
            f'{d}{body}</svg>')


def main():
    mode, theme = sys.argv[1], sys.argv[2]
    small = len(sys.argv) > 3 and sys.argv[3] == "small"
    t, g = THEMES[theme], (SMALL if small else FULL)
    d = defs(t, g)
    if mode == "background":
        print(svg(f'<g transform="{LAYER_T}">{background(t)}</g>', d))
    elif mode == "foreground":
        print(svg(f'<g transform="{LAYER_T}">{foreground(t, g, small)}</g>', d))
    elif mode == "square":
        print(svg(f'<g transform="{LAYER_T}">{background(t)}{foreground(t, g, small)}</g>', d))
    elif mode == "icon":
        sq = squircle(TILE_C, TILE_A, TILE_N)
        rc, ro = t["rim"]
        sh = (f'<use href="#sq" transform="translate(0 {14 if not small else 10})" fill="{t["tileShadow"]}" '
              f'opacity="{t["tileShadowOp"]}" filter="url(#b24)"/>') if not small else (
              f'<use href="#sq" transform="translate(0 12)" fill="{t["tileShadow"]}" '
              f'opacity="{t["tileShadowOp"]*0.8:.2f}" filter="url(#b24)"/>')
        rim = f'<use href="#sq" fill="none" stroke="{rc}" stroke-opacity="{ro}" stroke-width="5"/>' if not small else ""
        extra = f'<path id="sq" d="{sq}"/><clipPath id="clip"><use href="#sq"/></clipPath>'
        d = d.replace("<defs>", "<defs>" + extra, 1)
        print(svg(f'{sh}<g clip-path="url(#clip)">{background(t)}{foreground(t, g, small)}{rim}</g>', d))
    else:
        sys.exit(f"unknown mode {mode}")


if __name__ == "__main__":
    main()
