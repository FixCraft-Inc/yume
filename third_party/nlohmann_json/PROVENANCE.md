# nlohmann/json vendored provenance

Version 3.11.3, MIT licensed. Both files are **verbatim upstream release
assets**. Do not edit them, and do not hand-assemble a replacement out of
another one: this is a 25,000-line amalgamation, and a locally authored file
is one only its author knows how to regenerate at the next update.

| File | Upstream asset |
| --- | --- |
| `nlohmann/json.hpp` | https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp |
| `nlohmann/json_fwd.hpp` | https://github.com/nlohmann/json/releases/download/v3.11.3/json_fwd.hpp |

```text
json.hpp      sha256 9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6
json_fwd.hpp  sha256 5cefbba751baf5243033fd894c70be9b37103d64b3d3a959e4173197d71137b9
```

## Both files, not just json.hpp

`third_party/nlohmann_json` is first on the include path, so any nlohmann
header it does not supply is silently answered by whatever the build host has
installed, mixing two versions of the library into one translation unit. That
is not theoretical. Only `json.hpp` was vendored, `config/v1/config.hpp`
includes `<nlohmann/json_fwd.hpp>`, and every CI build lane failed inside the
vendored header while developer machines whose distribution happened to ship
3.11.3 built fine.

Take the release assets, not the multi-header distribution. Upstream's
`include/nlohmann/json_fwd.hpp` opens with
`#include <nlohmann/detail/abi_macros.hpp>` and belongs to a tree this
directory does not carry. The release asset of the same name is amalgamated
and self-contained.

## Updating

1. Download both assets for the new tag from the release page.
2. Replace both files together. They encode the same version and ABI tags and
   must not disagree about the inline namespace they open.
3. Update the version, URLs and hashes above.
4. Run `python3 -m unittest tests.test_project_metadata`, which pins these
   hashes and checks that the vendored tree satisfies every `<nlohmann/...>`
   include in the sources and in the vendored headers themselves.

If a local change ever becomes unavoidable, keep it as a named patch applied
on top of the pristine asset, the way `patches/openssl/series` does, so the
next update is a re-download plus a re-apply rather than a merge into a
monolith.
