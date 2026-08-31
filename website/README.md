# YUME website

Published to GitHub Pages by `.github/workflows/pages.yml`. Jekyll builds this
directory. `actions/configure-pages` injects the correct `baseurl`, which is why
every internal link goes through `relative_url` rather than a hand-written `../`
path.

## The docs here are generated, not written

`scripts/sync_website_docs.sh` runs before every build. It deletes
`website/docs/*.md` along with `docs/agents`, `docs/protocol`, and
`docs/release`, then regenerates them from the repository's own `docs/` tree,
adding front matter and rewriting cross-references into site links.

**Edit `docs/` at the repository root, never `website/docs/*.md`.** Anything
written directly into the generated files is lost on the next build.
`website/docs/index.html` is hand-written and is not touched by the sync, so the
docs landing page is safe to edit here.

## Where things live

| Path | What it is |
| --- | --- |
| `_config.yml` | Site settings. `asset_version` is the cache buster for CSS and JS. |
| `_data/nav.yml` | The header link list. Edit here, not in the pages. |
| `_includes/` | Shared chrome: `head`, `brand`, `site-header`, `section-nav`, `site-footer`, `theme-toggle`. |
| `_layouts/page.html` | Wrapper for the hand-written pages. |
| `_layouts/doc.html` | Wrapper for the generated Markdown docs. |
| `assets/tokens.css` | Colour, type, spacing, and motion tokens for both themes. |
| `assets/site.css` | Everything else. |
| `assets/site.js` | Release metadata, hashes, theme toggle, scroll spy, doc contents. |

## Common edits

**Add or rename a header link.** Edit `_data/nav.yml`. Every page reads it.

**Add a page.** Create an HTML file with `layout: page` front matter and a
`title`. Optional keys: `description`, `body_class`, `nav_current` (marks a
header link as current), `footer_statement` (the one line that differs between
page footers), and `section_nav` (the on-page anchor strip).

**Add a documentation page.** Add the Markdown to the repository's root `docs/`
directory. The sync script picks it up, and the on-page table of contents builds
itself from the `h2` and `h3` headings.

**Change a colour.** Edit `assets/tokens.css`. Light values sit on `:root` and
the dark palette is defined once in the `--dark-*` block and mapped onto the same
names. Both a `prefers-color-scheme` query and a `[data-theme]` selector do the
mapping, so a manual toggle wins in both directions.

**Ship a CSS or JS change.** Bump `asset_version` in `_config.yml`.

## Rules worth keeping

The mark is inlined as a `path` in `_includes/brand.html`. Do not go back to
`<use href="yume-plain.svg#yume-mark">`: WebKit has never supported external
references in `use`, so that markup rendered an empty box in Safari. Inlining
also keeps the `fill: currentColor` tinting that an `img` would lose.

Hover and focus states should not change an element's box, so that content does
not reflow under the pointer.

Motion is limited to the four cases documented at the top of the Motion section
in `site.css`. Scroll-triggered reveals on ordinary sections are deliberately
absent. This site is the soft half of the FixCraft pair, so its travel is longer
and its settle slower than the BaseFWX portal's.

Colour identity is the boundary against BaseFWX. YUME is plum at OKLCH hue 337
to 341 with generous rounding. BaseFWX is violet at hue 305 to 306 with
near-square corners. Keep the two apart.

Do not invent numbers or soften the status language. The page says the software
is experimental because it is.

## Working on it locally

```sh
bash scripts/sync_website_docs.sh
jekyll build -s website -d /tmp/yume-site
python3 -m http.server 8000 -d /tmp/yume-site
```

To check the project-page mount that Pages actually serves, add
`--baseurl /yume` to the build.

Before pushing, confirm there is no horizontal scroll at 320, 375, 414, and 768
pixels, and that the theme toggle round-trips and survives a reload.
