# YUME website design

This file locks the visual system for the YUME website. Homepage, utility pages,
and generated documentation use the same tokens and interaction rules.

## Genre

Soft and atmospheric, with technical copy kept plain. Light mode is the default
and carries the identity. Dark mode remains a supported reading option.

## Macrostructure family

- Homepage: Map / Diagram. The generated connection flow and layer figures are
  the spatial anchor.
- Utility and index pages: Index-first lists with the same soft shell.
- Documentation: Long Document with a persistent contents rail.

## Theme

YUME's colours are soft and natural, plum and sakura rather than a loud
accent, and they are one palette across the website, the desktop GUI and the
Android app: `config/palette.json`. Light and dark are separate designs, not
one ramp inverted. Every value is OKLCH on hue 338, the mark's own hue.

- Light: a faintly pink page `oklch(96.5% 0.0065 338)` under warm-white cards
  `oklch(99.3% 0.0035 338)`, plum ink, a dusty plum accent
  `oklch(54.5% 0.095 338)` for controls and links, and blossom main buttons
  `oklch(91.5% 0.042 338)` with plum text.
- Dark: a plum night page `oklch(19% 0.012 338)` under lifted cards
  `oklch(25% 0.015 338)`, and a soft pink accent and button
  `oklch(84.5% 0.072 338)` with wine text. The AMOLED variant puts the same
  dark theme on true black.

The palette also states the contrast each theme must keep (body text 7:1,
secondary text and the accent 4.5:1, field outlines 3:1), and
`scripts/yume_palette.py` refuses a change that breaks it. That script
generates the colour regions of `assets/tokens.css`, the desktop's
`Palette.js`, Android's `GeneratedPalette.kt` and the generated marks. Change a
colour only in the JSON. Do not add colour literals to `assets/site.css`.

### Mark

`src/gui/assets/icon.svg` is the original mark and the one source of its
shape: a pale gradient at about 86 % opacity, made to sit on white. Every
other mark fills that shape with the solid colours it shows over white,
`#ffcbf3` at the lower edge to `#e59fd1` at the top (`logoFrom` and `logoTo`
in the palette, `--color-logo-from` and `--color-logo-to` here): the site in
both themes, `assets/yume-mark.svg`, the Android launcher on its warm-white
tile, and the desktop sidebar, window and tray. Over white they look the same
as the original, and they stay true on any other ground. The mark is never
recoloured or darkened for dark grounds. Status-bar icons are the outline
alone in white.

### Diagram roles

Site chrome stays on the plum hue. Inside a figure, colour carries meaning,
and the same meaning holds in companion pages and the explainer video:

| Role | Hue | Stands for |
| --- | --- | --- |
| `client` | 338 plum | the YUME client (the brand accent) |
| `server` | 310 wisteria | yumed and its session |
| `data` | 245 sky | the reader's own traffic |
| `disguise` | 62 apricot | what makes the connection look ordinary |
| `keys` | 80 honey | sealing and key material |
| `outside` | 165 sage | destinations and the wider internet |
| `refused` | 18 rose | refused or still-visible things |
| `neutral` | 338 grey | plumbing a reader need not decode |

Each role has a mid tone, a strong ink, a soft tint and the ink on that tint
at matched lightness and low chroma in both themes (`--color-role-*`). The
apps use the same roles for states: sage when connected, apricot while
working, rose after a failure. Only the protected hop keeps the plum accent on
its line. Ordinary hops are quiet neutrals, and a branch takes the role of the
node it turns towards. A role is never used as a site accent.

## Typography

- Display: Quicksand, weight 600 or 700, normal style
- Body: Nunito Sans, weight 400 or 700
- Mono: IBM Plex Mono, weight 400 or 500
- Display tracking: `-0.025em`
- Display size: `clamp(3.25rem, 7vw, 5.25rem)`

## Spacing and shape

Use the named 4-point scale in `assets/tokens.css`. YUME surfaces are rounded,
but nested cards are not. Cloud shapes and uneven curves belong only to the mark
and transport passage.

## Motion

- Header: one DOM tree that compresses after 80 px of scroll
- Documentation: the reading progress bar is functional motion
- Diagrams: one packet travels the route on a slow loop, paused while the
  figure is off screen. A layers figure lights its rings in wrapping order
  instead. Pointing at a card or its key entry lights the pair and dims the
  rest, without changing any box.
- Reduced motion: content renders immediately, with no spatial travel

Animate only `transform` and `opacity`, with one exception: a diagram packet
travels its route with `offset-distance`, which is the only compositor-friendly
way to follow a path. It earns the exception because the path is the subject of
the figure. Scroll reveals use `IntersectionObserver`. If JavaScript fails, all
content stays visible and the packet keeps travelling.

## CTA voice

Buttons use short verbs: “Build from source”, “Read docs”, “View source”. The
primary action uses the pink fill. Secondary actions use a quiet paper surface.

## Page allowances

Homepage pages may use generated figures and the YUME mark. A figure and its key
come from `docs/diagrams/*.json` through the documentation sync, so the page
includes them and never hand-draws a route. The homepage sets stacked drawings
at their drawn size, two side by side on a wide screen, because a long band
scaled into the reading column shrinks its labels past legibility. Documentation uses typography and generated figures only. All pages share the same header, footer, focus treatment,
fonts, and colour tokens.

## Exports

`config/palette.json` is the canonical colour source and `assets/tokens.css`
the website's export of it. The portable core of the light theme is:

```css
:root {
  --color-paper: oklch(96.5% 0.0065 338);
  --color-cloud: oklch(99.3% 0.0035 338);
  --color-ink: oklch(26.5% 0.014 338);
  --color-accent-strong: oklch(54.5% 0.095 338);
  --color-button: oklch(91.5% 0.042 338);
  --color-focus: oklch(54.5% 0.095 338);
  --font-display: "Quicksand", ui-rounded, sans-serif;
  --font-body: "Nunito Sans", ui-sans-serif, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, monospace;
}
```
