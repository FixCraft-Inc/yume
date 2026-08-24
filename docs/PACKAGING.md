# Packaging YUME

This page covers local installs, man pages, and Debian package builds.

## Package Split

The Debian source packaging currently produces five YUME binary packages:

- `libyume1`: the stable C ABI runtime library.
- `libyume-dev`: the public C header, CMake config, and pkg-config file.
- `yume`: the command-line client, docs, and examples.
- `yume-daemon`: the `yumed` server daemon, disabled `yumed.service`,
  locked service user, `/etc/yume` config, and state/log/run directories.
- `yume-gui`: the optional desktop GUI, built unless
  `DEB_BUILD_PROFILES=nogui` is set.

BaseFWX is packaged separately as `basefwx`, `libbasefwx3`, and
`libbasefwx-dev`; YUME links to version `3.8.0~dev1-1` or newer for Debian
builds because the current 2.0 development line consumes the 3.8 X25519 and
ML-KEM-1024 APIs.
BaseFWX Debian archive builds must use packaged dependencies, including
`liboqs-dev`; vendored liboqs is only a local development override.
Full YUME packages also require OpenSSL 3.5 or newer: composite identities use
the ML-DSA-87 provider, so `debian/control` deliberately rejects older
`libssl-dev` packages instead of producing a binary that fails during AUTH.
The prepared `linux-desktop-0.2.0` archive is a separate contract: it links the
checksum-verified liboqs 0.16.0 archive statically, leaves OpenSSL dynamic with a declared 3.5
runtime floor, and rejects any `DT_RPATH`, `DT_RUNPATH`, or dynamic
`liboqs.so` dependency before copying an executable into the artifact.
`libyume` is the stable native C embed ABI. In 1.1 it exposes build metadata,
opaque client/server handles, and direct named service streams for projects
that need to embed YUME as their secure transport. YUME's `yume_core`,
`yume_client_lib`, `yume_server`, and `yume_facade` targets remain internal
static libraries so CLI/GUI/session refactors do not accidentally become ABI
breaks. See `docs/ABI.md` for the compatibility rules.

## Install From A Build Tree

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
sudo cmake --install build
sudo mandb
```

Installed files:

- `yume` and `yumed` go to the configured binary directory, usually
  `/usr/local/bin`.
- `yume-gui` goes to the configured binary directory when
  `YUME_BUILD_GUI=ON`.
- `yume(1)` goes to `share/man/man1`.
- `yumed(8)` goes to `share/man/man8`.
- `yume-gui(1)` goes to `share/man/man1` when the GUI is built.
- `libyume.so.1`, `include/yume/yume.h`, CMake config, and pkg-config
  metadata are installed when `YUME_BUILD_SHARED_ABI=ON`.
- Markdown docs go to `share/doc/yume`.

Use a different prefix with:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build -j"$(nproc)"
sudo cmake --install build
sudo mandb
```

## Install Only The Man Pages

For a manual development install:

```bash
sudo install -Dm644 docs/man/yume.1 /usr/local/share/man/man1/yume.1
sudo install -Dm644 docs/man/yumed.8 /usr/local/share/man/man8/yumed.8
sudo mandb

man yume
man yumed
```

## Build A Debian Package

The CMake project has CPack rules for Debian packages.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build -j"$(nproc)"
(cd build && cpack -G DEB)
```

Install the result:

```bash
sudo apt install ./build/yume_*.deb
man yume
man yumed
```

The CPack `.deb` is a single upstream convenience package. It includes the
binaries, man pages, and installed Markdown docs. That means users do not
need to install the man pages separately when they install `yume_*.deb`.
When `YUME_BUILD_SHARED_ABI=ON`, CPack switches to component packages for
DEB/TGZ output and uses the older upstream convenience split:
`libyume1`, `libyume-dev`, `yume`, and, when enabled, `yume-gui`.
Use the `debian/` packaging for archive-style source package review and the
`yume-daemon` systemd/sysusers/tmpfiles split.

For a native dynamic Debian build, CPack uses `dpkg-shlibdeps` by default
to infer shared-library dependencies. If you are building a static or
cross-architecture package and dependency scanning is wrong for your
toolchain, disable it:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
  -DYUME_DEB_SHLIBDEPS=OFF \
  -DYUME_BUILD_SHARED_ABI=ON
cmake --build build -j"$(nproc)"
(cd build && cpack -G DEB)
```

## Build A Debian Package With ezbuild

The easy path is:

```bash
./ezbuild.sh --deb
```

`ezbuild.sh` installs dependencies, prepares BaseFWX, configures the build,
compiles YUME, and runs CPack. The `.deb` is printed at the end. For release
evidence, use `BASEFWX_SYNC_MODE=pinned ./ezbuild.sh --deb`; pinned mode
refuses local BaseFWX changes and checks out the configured dependency commit.

Useful variants:

```bash
# Separate build directory
YUME_BUILD_DIR=build-deb ./ezbuild.sh --deb

# Extra CMake arguments
YUME_CMAKE_ARGS="-DCMAKE_INSTALL_PREFIX=/usr -DYUME_NATIVE_OPT=OFF" ./ezbuild.sh --deb

# Minimal/static package
./ezbuild.sh --minimal --deb
```

## Cross-Architecture Packages

`--arch` sets the target architecture metadata for CMake/CPack and lets
the script choose matching vendored dependency prefixes when available.

```bash
YUME_BUILD_DIR=build-arm64 \
YUME_TOOLCHAIN_FILE=/path/to/toolchain-arm64.cmake \
./ezbuild.sh --arch armv8 --deb
```

Common mappings:

| ezbuild arch | Debian arch |
| --- | --- |
| `x86_64`, `amd64` | `amd64` |
| `x86`, `i386`, `i686` | `i386` |
| `aarch64`, `arm64`, `armv8` | `arm64` |
| `armv7`, `armhf` | `armhf` |
| `mips`, `mipsel`, `mips64el` | same Debian name |

For cross builds, `ezbuild.sh --deb` disables `dpkg-shlibdeps`
automatically because host dependency scanning is usually wrong for
foreign binaries. Prefer static/minimal packages for simple distribution,
or provide a complete target sysroot and package dependencies manually. A
target sysroot with OpenSSL 3.0 is no longer sufficient for a full YUME build;
`YUME_TRANSPORT_CORE_ONLY` remains the intentionally crypto-free exception.

## Debian Main Packaging

Debian main does not accept upstream-built `.deb` files directly. Debian
accepts source packages built with Debian packaging metadata. This repo now
contains a `debian/` scaffold for that workflow:

- `debian/control`: source and binary package metadata.
- `debian/rules`: debhelper/CMake build entrypoint.
- `debian/changelog`: Debian package changelog.
- `debian/copyright`: machine-readable license and `Files-Excluded`.
- `debian/watch`: upstream release scanner.
- `debian/tests/*`: autopkgtest smoke and `libyume-dev` ABI consumer tests.

Run the lightweight source-package check before a full package build:

```bash
scripts/check_debian_source.sh
```

It creates and validates the upstream orig tarball, checks for accidentally
included local/private artifacts, runs `dpkg-source -b`, and removes the
generated source-package files when it exits.

Build the Debian-style binary package locally:

```bash
dpkg-buildpackage -us -uc -b
```

Build a source package for review:

```bash
scripts/make_debian_orig.sh
dpkg-buildpackage -S -us -uc
```

The helper writes `../yume_<version>.orig.tar.xz` and excludes bundled
dependency trees, vendored binaries, build directories, logs, bytecode, and
the `debian/` directory. The source package then contains the upstream
tarball plus Debian packaging metadata as a separate Debian tarball.
Development versions use Debian's sorting-safe spelling (`0.2.0-dev6` becomes
`1:0.2.0~dev6` with the packaging-only epoch). The epoch preserves upgrade
ordering across the upstream maturity reset and is omitted from archive
filenames. `scripts/check_debian_source.sh` rejects a mismatch between
`src/core/version.hpp` and the top Debian changelog entry.

The Debian package builds with:

```text
-DYUME_USE_BASEFWX=ON
-DYUME_USE_SYSTEM_BASEFWX=ON
-DYUME_USE_BUNDLED_NLOHMANN=OFF
-DYUME_BUILD_SHARED_ABI=ON
```

That means YUME must build against a separately packaged BaseFWX development
library. The intended package chain is:

```text
basefwx          optional command-line frontend
libbasefwx3      runtime shared library
libbasefwx-dev   headers, CMake config, pkg-config metadata
libyume1         stable C ABI runtime library
libyume-dev      yume.h, CMake config, pkg-config metadata
yume             client binary, docs, and examples
yume-daemon      yumed server, disabled yumed.service, /etc/yume config
yume-gui         optional desktop frontend, omitted by DEB_BUILD_PROFILES=nogui
```

The source-build default leaves `YUME_BUILD_SHARED_ABI=OFF` so a plain CMake
build still produces only `yume` and `yumed`. Debian turns it on because
library packages are part of the distribution contract. The C ABI should grow
through opaque handles and named service streams only; do not install private
C++ headers or expose raw `Tunnel` / server runtime classes.

CPack follows the same rule: no ABI option means one convenience package;
ABI enabled means component packages. This keeps quick source builds simple
while making SDK/package builds explicit.

Local CPack dependency scanning uses `dpkg-shlibdeps`. It can only infer
Debian package dependencies for libraries that were themselves installed from
Debian packages. If ML-KEM/liboqs is staged manually under `/usr/local`, the
generated local `.deb` assumes the target machine has that same library path
available. For archive-style packages, build through `debian/` against a
packaged `liboqs-dev` instead. CPack and `debian/control` also declare
`libssl3t64 (>= 3.5.0)` explicitly because generic OpenSSL provider lookups do
not give `dpkg-shlibdeps` a 3.5-only symbol from which to infer that runtime
floor.

For local testing, build BaseFWX first:

```bash
(cd basefwx && dpkg-buildpackage -us -uc -b)
sudo apt install ./libbasefwx3_*.deb ./libbasefwx-dev_*.deb ./basefwx_*.deb
dpkg-buildpackage -us -uc -b
```

If you cannot install packages on the build machine, extract the BaseFWX
packages and point the YUME build at that prefix:

```bash
rm -rf /tmp/yume-basefwx-prefix
mkdir -p /tmp/yume-basefwx-prefix
dpkg-deb -x libbasefwx3_*.deb /tmp/yume-basefwx-prefix
dpkg-deb -x libbasefwx-dev_*.deb /tmp/yume-basefwx-prefix
printf 'libbasefwx 3 libbasefwx3 (>= 3.8.0~dev1-1)\n' > debian/shlibs.local
BASEFWX_PREFIX=/tmp/yume-basefwx-prefix/usr \
BASEFWX_LIBDIR=/tmp/yume-basefwx-prefix/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH) \
dpkg-buildpackage -d -us -uc -b
rm -f debian/shlibs.local
```

For Debian main, BaseFWX itself must not hide a vendored or prebuilt liboqs.
If liboqs is not already available as a Debian package, it needs to be
packaged separately first. The local BaseFWX packaging can use
`../vendor/linux-x86_64` for ML-KEM-768 while testing, but that mode is not
the final archive-ready form.

Before asking for sponsorship:

- Replace `Closes: #nnnnnn` in `debian/changelog` with the real ITP bug.
- Replace the maintainer email if `debian@fixcraft.jp` is not real.
- Run `lintian` on the `.changes` file.
- Run the package in a clean build environment such as `sbuild` or
  `pbuilder`.
- Confirm the upstream tarball produced by `uscan` excludes `basefwx/`,
  `vendor/`, `third_party/`, build outputs, logs, and bytecode.
- Package liboqs separately or build against an existing Debian liboqs-dev
  package before claiming BaseFWX is Debian-main ready.

Typical new-package path:

1. File ITP bugs against Debian WNPP for the new source packages.
2. Build clean source packages for BaseFWX and YUME.
3. Upload them to mentors.debian.net.
4. File RFS bugs or contact `debian-mentors`.
5. A Debian Developer reviews and sponsors the uploads.
6. Because these are new packages, they go through the NEW queue before they
   can enter Debian.

## Validate ASCII Diagrams

The man pages and `docs/EXPLAINED.md` use fixed-width ASCII diagrams.
Run this before release:

```bash
python3 scripts/check_ascii_diagrams.py
groff -man -Tutf8 docs/man/yume.1 >/tmp/yume.man.txt
groff -man -Tutf8 docs/man/yumed.8 >/tmp/yumed.man.txt
```

The checker rejects old small boxes, unexpected box widths, and boxed rows
without padding.
