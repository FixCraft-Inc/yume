# Diagrams

Every route illustration YUME publishes is generated from one JSON file in this
directory. A single specification produces three renderings:

| Output | Where it lands |
| --- | --- |
| Fixed-width ASCII | the `.nf` blocks in `docs/man/*.1` and `docs/man/*.8` |
| The same ASCII | ```` ```text ```` fences in `docs/*.md` |
| Animated inline SVG | `website/_includes/diagrams/*.svg`, inlined by the site |

Edit the JSON, run one command, and all three move together. Nothing is
maintained in two places.

## Commands

```bash
scripts/yume_diagrams.py list                     # specifications and targets
scripts/yume_diagrams.py render direct_route      # the ASCII form
scripts/yume_diagrams.py render direct_route --svg --layout horizontal
scripts/yume_diagrams.py sync                     # write every output
scripts/yume_diagrams.py check                    # verify without writing
```

CI generates the ignored SVG includes with `scripts/sync_website_docs.sh`
before running `check`. Do the same in a fresh checkout. `check` fails when a block is stale, when a marker names a
diagram that does not exist, or when a specification claims a target file that
carries no marker for it.

`python3 scripts/test_yume_diagrams.py` generates SVGs in temporary storage.
The test suite, including its CTest entry, needs no prior website build.

## Adding a diagram

1. Write `docs/diagrams/<name>.json`. The `name` field must match the file
   name. Copy the shape of `direct_route.json`.
2. Place a marker pair where the ASCII should appear, leaving the body empty.

   In Markdown, an empty `text` fence between the two comments:

   ````markdown
   <!-- yume-diagram: my_route -->
   ```text
   ```
   <!-- /yume-diagram -->
   ````

   In a man page, an empty literal block between the two roff comments:

   ```roff
   .\" yume-diagram: my_route
   .nf
   .fi
   .\" /yume-diagram
   ```

3. List those files under `targets` in the specification.
4. Run `scripts/yume_diagrams.py sync`, then
   `python3 scripts/check_ascii_diagrams.py`.

The website substitution happens inside `scripts/sync_website_docs.sh`, which
replaces each marked block in the generated mirror with the animated SVG plus a
collapsed text version. Nothing extra is needed to publish a diagram, and the
canonical Markdown keeps its ASCII for terminals and for GitHub.

## Specification reference

| Key | Meaning |
| --- | --- |
| `name` | matches the file name, lowercase with underscores |
| `type` | `route` is the only type so far, an ordered chain of nodes |
| `title` | the accessible name of the figure |
| `summary` | one sentence, used as the SVG description and the web caption |
| `comment` | optional notes for maintainers, never rendered |
| `width` | optional, `34` or `72`, otherwise picked from the longest label |
| `indent` | optional leading spaces for a nested Markdown block |
| `targets` | `man` and `markdown` path lists plus a `web` flag |
| `nodes` | `id`, `kind`, `title`, and optional `sub` |
| `edges` | `from`, `to`, optional `label`, optional `channel` |

Node `kind` picks the SVG glyph and nothing else: `app`, `client`, `server`,
`target`, `relay`, `tor`, `tun`, or `cloud`.

Edge `channel` says what kind of hop it is. `plain` is an ordinary connection,
`tunnel` is the protected YUME carrier, and `onion` is a Tor circuit. The ASCII
form spells the channel as `==YUME==>` or `...>` because it has no other way to
show it. The SVG draws it as a walled channel or a dotted line instead, so a
label is only needed when the specification has real words to add.

## Rules

- Labels must fit the ASCII box. The validator rejects anything longer, which is
  also what keeps the SVG able to size its cards without font metrics.
- Every string drawn comes from the specification. Neither renderer invents a
  label, a hop, or a claim.
- The SVG carries no colours. It uses class names that
  `website/assets/site.css` styles from the tokens, so the theme toggle
  recolours a diagram with no second palette.
- Generated SVG under `website/_includes/diagrams/` is ignored by Git and
  rebuilt by CI, exactly like `website/docs/**/*.md`.
