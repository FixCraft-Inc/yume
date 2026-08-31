# YUME website design

This file locks the visual system for the YUME website. Homepage, utility pages,
and generated documentation use the same tokens and interaction rules.

## Genre

Soft and atmospheric, with technical copy kept plain. Light mode is the default
and carries the identity. Dark mode remains a supported reading option.

## Macrostructure family

- Homepage: Map / Diagram. The transport passage is the spatial anchor.
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
- Homepage: selected passage nodes drift into place once
- Documentation: the reading progress bar is functional motion
- Reduced motion: content renders immediately, with no spatial travel

Animate only `transform` and `opacity`. Scroll reveals use
`IntersectionObserver`. If JavaScript fails, all content stays visible.

## CTA voice

Buttons use short verbs: “Build from source”, “Read docs”, “View source”. The
primary action uses the pink fill. Secondary actions use a quiet paper surface.

## Page allowances

Homepage pages may use the CSS transport passage and the YUME mark. Documentation
uses typography only. All pages share the same header, footer, focus treatment,
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
