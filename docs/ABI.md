# YUME ABI Policy

YUME exposes a stable C ABI through `libyume.so.1` when configured with
`-DYUME_BUILD_SHARED_ABI=ON`.

The ABI is intentionally small. It currently exposes version, feature, and
backend information for external tools and packaging checks. It does not
export C++ classes, STL types, Boost.Asio types, OpenSSL handles, or internal
client/server session objects.

## Why C ABI First

The CLI, GUI, facade, and transport internals are still being refactored.
Exporting C++ classes now would freeze compiler, standard library, exception,
allocator, and object-layout details before those boundaries are ready. A C
ABI keeps the Debian package useful while allowing internal cleanup to
continue.

## Compatibility Rules

- `YUME_ABI_VERSION` tracks source-level C ABI shape.
- `libyume.so.1` tracks binary runtime compatibility.
- Existing exported functions must keep their names, return conventions, and
  argument meaning for the lifetime of SONAME `1`.
- Structs that cross the ABI must start with `struct_size`.
- New fields may only be appended to public structs.
- Functions must not throw exceptions across the ABI.
- Returned strings are owned by the library and remain valid for the process
  lifetime.
- Do not expose internal C++ headers from `src/`.

## Build Behavior

Source builds keep the ABI library off by default:

```bash
cmake -B build
cmake --build build
```

Enable it explicitly when building SDK/install artifacts:

```bash
cmake -B build -DYUME_BUILD_SHARED_ABI=ON
cmake --build build --target yume_abi
```

Debian packaging enables the ABI library by default and splits it as:

- `libyume1`: runtime shared library.
- `libyume-dev`: `yume.h`, CMake config, and pkg-config metadata.
- `yume`: CLI client and `yumed` server daemon.
- `yume-gui`: optional GUI, omitted by `DEB_BUILD_PROFILES=nogui`.

## Future Expansion

Client/server control APIs should be added only as opaque C handles after the
facade contract is deliberately designed. Avoid exposing raw transport streams
or GUI models; those should remain internal implementation details.
