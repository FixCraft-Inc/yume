# YUME website

Published to GitHub Pages by `.github/workflows/pages.yml`. Jekyll builds this
directory. `actions/configure-pages` injects the correct `baseurl`, which is why
every internal link goes through `relative_url` rather than a hand-written `../`
path.

## Documentation sources

Documentation text and metadata are authored in `docs/src/en_US/*.doc`
(recursively), outside this website tree. Edit the source named by a generated
file and run `python3 scripts/yume_docs.py sync --all-languages` from the
repository root. This produces pages, catalog, manuals, Markdown, SVGs and
YUME help headers. `scripts/sync_website_docs.sh` is the website-only entry
point used by CI. It calls the same renderer.

`python3 scripts/yume_docs.py check --all-languages` checks tracked outputs;
`python3 scripts/check_website_catalog.py` checks the generated website too.
Page titles, descriptions, catalog titles and summaries come from the same
`.doc` as the body. See [the authoring guide](../docs/src/README.md).
`website/docs/index.html` is authored HTML; its layout remains editable here.

## Where things live

| Path | What it is |
| --- | --- |
| `_config.yml` | Site settings. `asset_version` is the cache buster for CSS and JS. |
| `_data/nav.yml` | The header link list. Edit here, not in the pages. |
| `_data/docs.json` | Generated from document headers; edit the owning `.doc` title, summary, route and catalog fields. |
| `_includes/` | Shared chrome: `head`, `brand`, `site-header`, `section-nav`, `site-footer`, `theme-toggle`. |
| `_layouts/page.html` | Wrapper for the hand-written pages. |
| `_layouts/doc.html` | Wrapper for the generated Markdown docs. |
| `assets/tokens.css` | Colour, type, spacing, and motion tokens for both themes. |
| `assets/site.css` | Everything else. |
| `assets/site.js` | Release metadata, hashes, theme toggle, scroll spy, doc contents. |
| `DESIGN.md` | The locked visual and motion rules for every website route. |

## Common edits

**Add or rename a header link.** Edit `_data/nav.yml`. Every page reads it.

**Add a page.** Create an HTML file with `layout: page` front matter and a
`title`. Optional keys: `description`, `body_class`, `nav_current` (marks a
header link as current), `footer_statement` (the one line that differs between
page footers), and `section_nav` (the on-page anchor strip).

**Add a documentation page.** Create a `.doc` under `docs/src/en_US/pages/`
with `web: yes`. Put its title, summary and optional catalog placement in that
header and run the unified sync. Existing output paths and explicit
`web-path` values preserve incoming links.

**Change a colour.** Edit `assets/tokens.css`. Light values sit on `:root` and
the dark palette is defined once in the `--dark-*` block and mapped onto the same
names. Both a `prefers-color-scheme` query and a `[data-theme]` selector do the
mapping, so a manual toggle wins in both directions.

**Ship a CSS or JS change.** Bump `asset_version` in `_config.yml`.

## Rules worth keeping

The mark is an inline `path` in `_includes/brand.html`. Keep it inline to
avoid cross-file SVG references and preserve `fill: currentColor` tinting.

Hover and focus states should not change an element's box, so that content does
not reflow under the pointer.

Motion follows the rules in `DESIGN.md`. The header compresses after a deliberate
scroll, and selected transport-path elements reveal once through
`IntersectionObserver`. Content remains visible when JavaScript fails. Reduced
motion removes spatial travel.

Colour identity is the boundary against BaseFWX. YUME is plum at OKLCH hue 337
to 341 with generous rounding. BaseFWX is violet at hue 305 to 306 with
near-square corners. Keep the two apart.

Do not invent numbers or soften the status language. The page says the software
is experimental because it is.

## Working on it locally

```sh
bash scripts/sync_website_docs.sh
python3 scripts/check_website_catalog.py
jekyll build -s website -d /tmp/yume-site --baseurl /yume
python3 -m http.server 8000 -d /tmp/yume-site
```

CI and Pages generate the ignored mirror before catalog validation and the
Jekyll build. Optional `bash scripts/sync_website_docs.sh --check` does not
write files; it compares an already-generated local mirror with the document
sources. It is not a clean-checkout gate because the mirror is intentionally
absent there. The base URL matches the GitHub project-page mount.

Before pushing, confirm there is no horizontal scroll at 320, 375, 414, and 768
pixels, and that the theme toggle round-trips and survives a reload.
