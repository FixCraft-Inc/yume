# YUME Linux release third-party notices

YUME is distributed under the GNU Affero General Public License version 3 or
later; see `LICENSE` in the bundle. The Linux binaries also use or incorporate
the following projects under their respective licenses:

- BaseFWX: GPL-3.0-or-later. Its pinned source revision is recorded in
  the `basefwx` entry in `config/dependencies.json` in the matching YUME source
  release.
- Boost: Boost Software License 1.0.
- OpenSSL: Apache License 2.0.
- YUME's downstream OpenSSL patch overlay: AGPL-3.0-or-later. The underlying
  OpenSSL source remains under Apache-2.0.
- Brotli: MIT License.
- nghttp2: MIT License.
- zlib: zlib License.
- XZ Utils/liblzma: public domain and LGPL components as documented upstream.
- Zstandard: BSD 3-Clause License and GPLv2 dual license.
- Argon2 reference implementation: CC0 1.0 or Apache License 2.0.
- liboqs: MIT License.
- spdlog: MIT License.
- nlohmann/json: MIT License.
- uTLS and Go module dependencies used by `yume-chrome-tls-helper`: BSD,
  MIT, and Apache-2.0 terms recorded by the corresponding pinned modules in
  `helper/chrome_tls/go.mod` and `helper/chrome_tls/go.sum`.
- The Go toolchain/runtime: BSD 3-Clause License.

The matching source release and dependency repositories contain the complete
license texts and copyright notices. This summary does not replace those
terms.
