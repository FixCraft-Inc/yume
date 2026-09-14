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

- Paper: `oklch(98.8% 0.008 337)`
- Soft paper: `oklch(96.5% 0.025 337)`
- Ink: `oklch(31% 0.025 337)`
- Muted ink: `oklch(49% 0.03 337)`
- Rule: `oklch(88% 0.025 337)`
- Pink accent: `oklch(78% 0.12 337)`
- Focus: `oklch(52% 0.15 337)`

The complete light and dark ramps live in `assets/tokens.css`. Do not add colour
literals to `assets/site.css`.

### Diagram roles

Site chrome stays on the plum axis. Inside a figure, colour carries meaning,
and the same meaning holds in companion pages and the explainer video:

| Role | Hue | Stands for |
| --- | --- | --- |
| `client` | 337 plum | the YUME client (the brand accent) |
| `server` | 295 iris | yumed and its session |
| `data` | 245 blue | the reader's own traffic |
| `disguise` | 60 amber | what makes the connection look ordinary |
| `keys` | 92 yellow | sealing and key material |
| `outside` | 165 mint | destinations and the wider internet |
| `refused` | 25 coral | refused or still-visible things |
| `neutral` | 337 grey | plumbing a reader need not decode |

Each role has a mid tone, a strong ink and a soft tint at matched lightness in
both themes (`--color-role-*`). Only the protected hop keeps the plum accent on
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
includes them and never hand-draws a route. On a phone the stacked drawing
replaces the band. Documentation uses typography and generated figures only. All pages share the same header, footer, focus treatment,
fonts, and colour tokens.

## Exports

`assets/tokens.css` is the canonical export. The equivalent portable core is:

```css
:root {
  --color-paper: oklch(98.8% 0.008 337);
  --color-ink: oklch(31% 0.025 337);
  --color-rule: oklch(88% 0.025 337);
  --color-accent: oklch(78% 0.12 337);
  --color-focus: oklch(52% 0.15 337);
  --font-display: "Quicksand", ui-rounded, sans-serif;
  --font-body: "Nunito Sans", ui-sans-serif, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, monospace;
}
```
