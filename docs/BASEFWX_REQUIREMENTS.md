# BaseFWX requirements discovered by YUME

Status: tracked cross-repository requirement and integration record. Signed,
published BaseFWX commit `e6ffbb79daa02bf62c31c3ae6513d5c603ec8dcd`
implements BFX-YUME-001, and the current YUME source pins and consumes it when
`YUME_USE_BASEFWX=ON`. Repository order remains strict: BaseFWX must be
committed, pushed, and remotely reachable before YUME records that revision in
`config/dependencies.json`.

## BFX-YUME-001: owned ChaCha20-Poly1305 one-shot API

YUME relay-history records use this frozen storage shape:

```text
12-byte nonce || ciphertext || 16-byte Poly1305 tag
```

The former pinned BaseFWX C++ API exposed owned/staged AES-GCM helpers, but no
ChaCha20-Poly1305 helper that accepted an explicit nonce and AAD. Replacing the
history primitive with AES-GCM would have silently changed existing protected
history records, so this requirement added the missing primitive instead.

The BaseFWX change provides these public C++ operations:

```cpp
Bytes ChaCha20Poly1305EncryptWithIv(
    const Bytes& key, const Bytes& iv,
    const Bytes& plaintext, const Bytes& aad);

Bytes ChaCha20Poly1305DecryptWithIvOwned(
    const Bytes& key, const Bytes& iv,
    const std::uint8_t* blob, std::size_t blob_len,
    const Bytes& aad);
```

Acceptance requirements:

- require exactly a 32-byte key and 12-byte nonce;
- encode the result as `ciphertext || 16-byte tag` so YUME can migrate without
  changing its on-disk record format;
- stage plaintext in wiping, move-only storage and publish it only after tag
  verification;
- reject oversized inputs before narrowing a length to OpenSSL `int`;
- accept explicit AAD, including an intentionally empty vector for the legacy
  YUME history format;
- cover empty/nonempty plaintext, tampered ciphertext/tag/AAD, wrong key/nonce,
  boundary lengths, and proof that caller output remains unpublished on
  authentication failure;
- follow BaseFWX's compatibility, security, language-parity, release, and
  version-synchronization policies before publication.

## Implementation and integration boundary

The separate pinned BaseFWX revision contains the two C++ operations above plus
RFC 8439, fixed empty-AAD, empty-plaintext, tamper, key/nonce, structural,
pointer, and length-boundary regressions. Its compatibility policy explicitly
limits this candidate to C++: the only intended consumer is YUME's existing
at-rest history format, and no BaseFWX cross-runtime wire or file format uses
the primitive. Java/Python parity is not claimed; a future BaseFWX format or a
second-runtime consumer would acquire the full parity and shared-KAT
obligation.

YUME's default history helper now delegates to these operations with explicit
empty AAD. The `YUME_USE_BASEFWX=OFF` build retains the local raw-OpenSSL
fallback for that supported configuration; it remains fail-closed and wipes
unauthenticated plaintext. Live callers must not expand that fallback.

The YUME relay-persistence regression decrypts a fixed record produced before
the delegation and proves new output retains the exact
`12-byte nonce || ciphertext || 16-byte tag` shape. RFC conformance and
BaseFWX's empty-AAD fixtures independently pin the primitive. Together these
gates cover the formerly missing migrated-caller round trip.

The exact 355-file BaseFWX candidate passed its complete Python/C++/Java
functional and cross-runtime matrix (181/181 operations), native CTest policy
executables, bounded active-surface benchmark matrix (15/15 reported rows per
runtime), plugin ABI smoke (17/17 steps), and the Git-less frozen-source
archive privacy gate before the signed commit was published. Those results
qualify BaseFWX itself; YUME still requires its own exact-pin build and test
matrix before this integration is accepted.

Java/Python parity remains intentionally out of scope because no BaseFWX wire
or cross-runtime file format consumes this helper. A future second-runtime or
BaseFWX-format consumer acquires the full shared-KAT and parity obligation.
