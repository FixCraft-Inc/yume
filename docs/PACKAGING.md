# Packaging YUME

This page covers local installs, man pages, and Debian package builds.

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
- `yume(1)` goes to `share/man/man1`.
- `yumed(8)` goes to `share/man/man8`.
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

The `.deb` includes the binaries, man pages, and installed Markdown docs.
That means users do not need to install the man pages separately when they
install `yume_*.deb`.

For a native dynamic Debian build, CPack uses `dpkg-shlibdeps` by default
to infer shared-library dependencies. If you are building a static or
cross-architecture package and dependency scanning is wrong for your
toolchain, disable it:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
  -DYUME_DEB_SHLIBDEPS=OFF
cmake --build build -j"$(nproc)"
(cd build && cpack -G DEB)
```

## Build A Debian Package With ezbuild

The easy path is:

```bash
./ezbuild.sh --deb
```

`ezbuild.sh` installs dependencies, syncs BaseFWX, configures the build,
compiles YUME, and runs CPack. The `.deb` is printed at the end.

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
or provide a complete target sysroot and package dependencies manually.

## Debian Main Packaging

Debian main does not accept upstream-built `.deb` files directly. Debian
accepts source packages built with Debian packaging metadata. This repo now
contains a `debian/` scaffold for that workflow:

- `debian/control`: source and binary package metadata.
- `debian/rules`: debhelper/CMake build entrypoint.
- `debian/changelog`: Debian package changelog.
- `debian/copyright`: machine-readable license and `Files-Excluded`.
- `debian/watch`: upstream release scanner.
- `debian/tests/*`: basic autopkgtest smoke test.

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

The Debian package builds with:

```text
-DYUME_USE_BASEFWX=ON
-DYUME_USE_SYSTEM_BASEFWX=ON
-DYUME_USE_BUNDLED_NLOHMANN=OFF
```

That means YUME must build against a separately packaged BaseFWX development
library. The intended package chain is:

```text
basefwx          optional command-line frontend
libbasefwx3      runtime shared library
libbasefwx-dev   headers, CMake config, pkg-config metadata
yume             client/server binaries linked to libbasefwx3
```

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
printf 'libbasefwx 3 libbasefwx3 (>= 3.6.4-1)\n' > debian/shlibs.local
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
