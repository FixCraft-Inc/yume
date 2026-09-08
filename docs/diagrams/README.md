# Diagrams

Every route illustration YUME publishes is generated from one JSON file in this
directory. A single specification produces three renderings:

| Output | Where it lands |
| --- | --- |
| ASCII | the `.nf` blocks in `docs/man/*.1` and `docs/man/*.8` |
| A figure plus the same ASCII | the marked blocks in `docs/*.md` |
| The same figure, inlined | the website, which styles it from its own tokens |

Edit the JSON, run one command, and all three move together. Nothing is
maintained in two places.

## Commands

```bash
scripts/yume_diagrams.py list                     # specifications and targets
scripts/yume_diagrams.py render direct_route      # the ASCII form
scripts/yume_diagrams.py render direct_route --svg --layout horizontal
python3 scripts/yume_docs.py sync --all-languages  # write every documentation layer
scripts/yume_diagrams.py check                    # verify without writing
scripts/yume_diagrams.py preview                  # a page showing both renderings
```

`check` fails when a block is stale, when a rendered SVG differs from its
specification, when a marker names a diagram that does not exist, or when a
document places a figure whose generated output carries no marker for it. It needs no
prior website build.

`preview` writes `website/_includes/diagrams/preview.html`. Open it to see every
diagram twice: once inlined, where the page's theme control recolours it, and
once through `<img>`, which is the sandbox GitHub and a file viewer use. Both
should look the same.

`python3 scripts/test_yume_diagrams.py` covers the specification grammar, both
renderers, and the generated Markdown block.

## Where the rendered SVG lives

`docs/diagrams/*.svg` is generated and tracked. A Markdown document points at
one so GitHub can draw it, which only works for a file that is committed.
`check` proves it matches its specification, so a stale commit fails CI.

`website/_includes/diagrams/` holds the same bytes for Jekyll to inline. That
copy is ignored and rebuilt by `scripts/sync_website_docs.sh`.

## How a figure is styled

The SVG paints and animates itself. Colors and fonts are derived from `website/assets/tokens.css`. Each color
reads its website token first and falls back to a generated sRGB value:

```css
fill: var(--color-cloud, #fffcfe);
```

Inlined by the website, `--color-cloud` is defined, so the theme toggle still
controls the figure and there is no second palette. Opened anywhere else the
token is absent and the fallback applies, with a `prefers-color-scheme` block
swapping only the fallbacks. That block is inert wherever the tokens exist, so
an explicit light theme on a dark desktop still wins. In an `<img>` the figure
follows the colour scheme of the page embedding it, which is how a GitHub
document gets a diagram that matches its theme.

Under the stylesheet every painted element also carries its light-theme value
as a presentation attribute. Those lose to any stylesheet rule, so they change
nothing in a browser, and they are what a renderer without CSS support draws
instead of SVG's default black fill.

The two themes separate a card from the ground differently, which is what
`website/assets/tokens.css` says they should. Dark steps the lightness, so a
card is plainly a lighter shape on a darker one. Light has `--color-paper` and
`--color-cloud` within a percent of each other, so the shadow behind a card is
what makes it an object rather than a hairline outline. That is why the soft
shape behind a card stands proud of it and sits a little below it, and why a
node lighting up uses `--color-accent` for its glow, which is a mid pink in
both themes, but `--color-accent-strong` for the filled chip, which has to
carry a knocked-out glyph. On a near-white page nothing can be brighter than
the page, so a glow there is read as colour rather than as brightness.

`website/assets/site.css` keeps only what the figure cannot know about the page
around it: it hides the standalone ground, because the page already has one,
and pauses motion in a figure that has scrolled out of view.

A packet is always in one of two places, on a wire or inside a node, and the
figure draws both. One packet travels the route along the line each hop is
actually drawn along, rather than from card centre to card centre, so it stays
on the arrow through a diagonal. It is drawn under the cards, so it disappears
into one node and comes out of the next. While it is inside a card, that card
is lit: a glow around it and its glyph knocked out of a filled chip. The two
halves run off one clock and are exactly complementary, so nothing is ever
happening off-screen and no two nodes are ever lit at once. The card's border
takes no part in this, because it already says whether the node is YUME
software and one mark cannot carry two meanings.

The loop turns over while the packet is inside the last card. The last node
goes dark as the first lights up, which is the next packet setting off.

Inside a conduit the carrier moves. All of it stops under
`prefers-reduced-motion`.

The packet crosses every figure at one rate, so a route takes longer to travel
because it is longer. Timing the loop by hop count instead made the same route
cross its stacked drawing at half the speed of its across-the-page drawing,
which said something about the layout rather than about the route.

## Adding a diagram

1. Write `docs/diagrams/<name>.json`. The `name` field must match the file
   name. Copy the shape of `direct_route.json`.
2. Place `@diagram <name>` in each `.doc` that needs it. The document owns
   placement; the specification does not repeat target paths.
3. Run `python3 scripts/yume_docs.py sync --all-languages`, followed by its
   `check` command and `python3 scripts/check_ascii_diagrams.py`.

Generated marker blocks contain the SVG and expandable ASCII in Markdown,
and escaped ASCII in roff. Do not edit the markers or their contents.

## How the ASCII form is drawn

The ASCII figure is drawn on a character canvas rather than assembled from
rows of equal boxes, so a route descends across the page instead of straight
down it. Each hop leaves a `+` port on the box border below it, runs diagonally when space permits, and lands on the port of the box it reaches. A figure
that is connected reads as one drawing, where a line merely passing near a
box reads as two.

Two rules bound the drawing. A box is sized to the longest label in its own
figure, and the whole block stays inside `yume_diagram_ascii.BUDGET` columns
so a manual's literal indent still leaves it inside a terminal at eighty. A
route wide enough that leaning would break the budget uses a
straight descent when the diagonal layout does not fit, and rejects labels too wide even for that layout.

`scripts/check_ascii_diagrams.py` owns the property no specification can
state, which is that a literal region renders as a figure at all: one box's
lines agree on width and indent, a boxed row is padded on both sides, and no
figure line is wide enough to fold. It also checks BaseFWX's generated flow figures and remaining literal
field and package diagrams.

## Specification reference

| Key | Meaning |
| --- | --- |
| `name` | matches the file name, lowercase with underscores |
| `type` | `route` is the only type so far, an ordered chain of nodes |
| `title` | the accessible name of the figure |
| `summary` | one sentence, used as the SVG description and the web caption |
| `comment` | optional notes for maintainers, never rendered |
| `width` | optional SVG card tier, `34` or `72`, otherwise picked from the longest label |
| `indent` | optional leading spaces for a nested Markdown block |
| `targets` | `web` controls SVG generation; `.doc` sources own placement |
| `nodes` | `id`, `kind`, `title`, optional `sub`, optional `group` |
| `edges` | `from`, `to`, optional `label`, optional `channel` |

Node `kind` picks the glyph, and it decides one other thing: `client`,
`server`, `relay`, and `tun` are YUME software, so those cards carry the accent
and everything the route only reaches stays neutral. That is a software
boundary, not a trust claim. `yumed` still terminates the tunnel and sees the
traffic it forwards.

Node `group` puts a run of adjacent nodes inside one named enclosure: the two
peers of a federation cluster, the three relays of a Tor circuit. Members must
be adjacent, a group needs at least two of them, and the title is at most 28
characters. Across the page an enclosure also lifts its members onto a plateau,
so the hops onto and off it run diagonally and the figure gets a shape of its
own rather than another row of equal boxes.

The ASCII form ignores `group` exactly as it ignores `kind`: a man page draws
the same node chain either way. That is the constraint on a group title. It may
name the nodes it encloses and it may not carry a claim they do not already
make, because a terminal reader never sees it.

Edge `channel` says what kind of hop it is. `plain` is an ordinary connection,
`tunnel` is the protected YUME carrier, and `onion` is a Tor circuit. The ASCII
form spells the channel as `==YUME==>` or `...>` because it has no other way to
show it. The SVG draws a tunnel as a conduit with the carrier moving inside it
and an onion hop as a dotted line, so a label is only needed when the
specification has real words to add.

Both layouts are generated for every diagram. `vertical` is a stack read top to
bottom and is what a Markdown document and a documentation page use. The
`horizontal` layout is the same drawing rotated, for a page where a route is
the spatial anchor.

## Translating a figure

A specification holds the topology and the source-language strings. The
topology is not translatable: the nodes, the hops, and which of them YUME
runs are the same drawing in every language.

Only the words change, and every figure's words for one language live in a
single `docs/src/<language>/diagrams.json`, so adding a language adds one
file rather than one per figure. An entry names the diagram and supplies any
of `title`, `summary`, `nodes`, `edges`, and `groups`. Keys are checked
against the specification, so an unknown diagram, node, hop, or group is an
error rather than a string that silently never appears.

An untranslated string keeps its source text, which lets a language land one
figure at a time. `scripts/yume_diagrams.py translations --language <lang>`
reports what is still missing.

Each language draws into its own directory, because the labels inside a
figure are the thing being translated. `en_US` keeps `docs/diagrams/*.svg`,
which documents already point at, and another language writes
`docs/diagrams/<language>/*.svg`. `scripts/yume_diagrams.py svg --language
<lang>` renders them.

A translated label is measured the same way a source label is. One that no
longer fits its box is rejected, because a translation can break a drawing
just as easily as a source string can. The ASCII form sizes each box to the
longest label in that language, so a figure that says less in one language is
drawn narrower there.

## Rules

- Labels must fit the SVG card tier. The validator rejects anything longer,
  which is what keeps the SVG able to size its cards without font metrics. The
  ASCII form sizes each figure to its own longest label instead, so a diagram
  that says less is drawn narrower.
- Every string drawn comes from the specification. Neither renderer invents a
  label, a hop, or a claim.
- Nothing in the SVG uses a `transform` attribute. A hop and its arrow head are
  computed at whatever angle they run, because `website/assets/site.css` resets
  transforms inside a revealed section and would drop them.
- Motion states something or it is not added. A packet's route, speed, size,
  and shape each have to stand for something the specification says, the same
  way a card's accent stands for the software boundary and a conduit stands
  for the protected hop. Decoration that means nothing is worse than stillness,
  because a reader will look for the meaning.
- Geometry is integer or two-decimal and the element order is fixed, so two
  runs over the same specification produce identical bytes.
