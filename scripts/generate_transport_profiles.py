#!/usr/bin/env python3
"""Generate immutable C++ and Go transport-profile registries from evidence."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "config" / "transport_profiles.json"
DEFAULT_OUTPUT = ROOT / "src" / "core" / "stealth" / "transport_profiles.inc"
DEFAULT_GO_OUTPUT = ROOT / "helper" / "chrome_tls" / "transport_profiles_generated.go"
DEFAULT_VERSION_HEADER = ROOT / "src" / "core" / "version.hpp"
MAX_JSON_BYTES = 4 * 1024 * 1024
PROFILE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
ALIAS_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
HEX16_RE = re.compile(r"0x[0-9a-f]{4}")
HELPER_PROVIDERS = {
    "chrome151": ("chrome151Spec", "Chrome 151"),
}


class ProfileError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileError(message)


def read_json(path: pathlib.Path) -> Any:
    require(path.is_file(), f"missing JSON file: {path}")
    require(path.stat().st_size <= MAX_JSON_BYTES,
            f"JSON file exceeds {MAX_JSON_BYTES} bytes: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError(f"cannot parse {path}: {error}") from error


def text(value: Any, field: str, *, maximum: int = 4096) -> str:
    require(isinstance(value, str), f"{field} must be a string")
    require(0 < len(value) <= maximum,
            f"{field} must contain 1..{maximum} characters")
    require("\x00" not in value, f"{field} must not contain NUL")
    return value


def integer(value: Any, field: str, *, minimum: int = 0,
            maximum: int = 0xFFFFFFFF) -> int:
    require(isinstance(value, int) and not isinstance(value, bool),
            f"{field} must be an integer")
    require(minimum <= value <= maximum,
            f"{field} must be in {minimum}..{maximum}")
    return value


def cpp_string(value: str) -> str:
    # JSON string escaping is a strict subset of the C++ escapes used here.
    return json.dumps(value, ensure_ascii=True)


def evidence_profile(path: pathlib.Path = DEFAULT_VERSION_HEADER) -> str:
    source = path.read_text(encoding="utf-8")
    matches = re.findall(
        r'kEvidenceProfile\s*=\s*(?:\n\s*)?"([^"]+)"', source
    )
    require(len(matches) == 1,
            f"expected exactly one kEvidenceProfile declaration in {path}")
    require(PROFILE_ID_RE.fullmatch(matches[0]) is not None,
            "evidence transport profile has an invalid ID")
    return matches[0]


def fixture_path(value: Any, profile_id: str) -> pathlib.Path:
    relative = pathlib.PurePosixPath(text(value, f"{profile_id}.fixture", maximum=256))
    require(not relative.is_absolute() and ".." not in relative.parts,
            f"{profile_id}.fixture must stay inside the repository")
    resolved = (ROOT / pathlib.Path(*relative.parts)).resolve()
    require(resolved.is_relative_to(ROOT.resolve()),
            f"{profile_id}.fixture escapes the repository")
    require(resolved.is_dir(), f"fixture directory does not exist: {relative}")
    return resolved


def artifact_path(fixture: pathlib.Path, value: Any, field: str) -> pathlib.Path:
    relative = pathlib.PurePosixPath(text(value, field, maximum=256))
    require(not relative.is_absolute() and ".." not in relative.parts,
            f"{field} must stay inside its fixture directory")
    resolved = (fixture / pathlib.Path(*relative.parts)).resolve()
    require(resolved.is_relative_to(fixture),
            f"{field} escapes its fixture directory")
    require(resolved.is_file(), f"artifact does not exist: {relative}")
    return resolved


def profile_artifacts(entry: dict[str, Any], fixture: pathlib.Path,
                      profile_id: str) -> dict[str, Any]:
    values = entry.get("artifacts")
    require(isinstance(values, dict), f"{profile_id}.artifacts must be an object")
    candidates = values.get("tls_wire_candidates")
    require(isinstance(candidates, list) and 1 <= len(candidates) <= 32,
            f"{profile_id}.artifacts.tls_wire_candidates must contain 1..32 files")
    resolved_candidates = [
        artifact_path(fixture, candidate,
                      f"{profile_id}.artifacts.tls_wire_candidates[{index}]")
        for index, candidate in enumerate(candidates)
    ]
    require(len(set(resolved_candidates)) == len(resolved_candidates),
            f"{profile_id}.artifacts.tls_wire_candidates contains duplicates")
    return {
        "manifest": artifact_path(
            fixture, values.get("manifest"), f"{profile_id}.artifacts.manifest"),
        "http2_profile": artifact_path(
            fixture, values.get("http2_profile"),
            f"{profile_id}.artifacts.http2_profile"),
        "tls_wire_profile": artifact_path(
            fixture, values.get("tls_wire_profile"),
            f"{profile_id}.artifacts.tls_wire_profile"),
        "tls_wire_candidates": resolved_candidates,
    }


def headers(value: Any, field: str) -> list[tuple[str, str]]:
    require(isinstance(value, list) and len(value) <= 64,
            f"{field} must be an array with at most 64 headers")
    result: list[tuple[str, str]] = []
    for index, pair in enumerate(value):
        require(isinstance(pair, list) and len(pair) == 2,
                f"{field}[{index}] must be [name, value]")
        result.append((text(pair[0], f"{field}[{index}].name", maximum=256),
                       text(pair[1], f"{field}[{index}].value", maximum=8192)))
    return result


def header_value(items: list[tuple[str, str]], name: str, field: str) -> str:
    matches = [value for key, value in items if key == name]
    require(len(matches) == 1, f"{field} must contain exactly one {name} header")
    return matches[0]


def setting_rows(value: Any, field: str) -> list[tuple[int, int]]:
    require(isinstance(value, list) and len(value) <= 32,
            f"{field} must be an array with at most 32 settings")
    result: list[tuple[int, int]] = []
    for index, row in enumerate(value):
        require(isinstance(row, list) and len(row) >= 2,
                f"{field}[{index}] must contain id and value")
        result.append((integer(row[0], f"{field}[{index}].id"),
                       integer(row[1], f"{field}[{index}].value")))
    return result


def priority(value: Any, field: str, *, parent_override: int | None = None) -> tuple[int, int, bool]:
    require(isinstance(value, dict), f"{field} must be an object")
    parent = integer(value.get("parent_stream_id"), f"{field}.parent_stream_id",
                     maximum=0x7FFFFFFF)
    if parent_override is not None:
        parent = parent_override
    weight = integer(value.get("weight"), f"{field}.weight", minimum=1, maximum=256)
    exclusive = value.get("exclusive")
    require(isinstance(exclusive, bool), f"{field}.exclusive must be boolean")
    return parent, weight, exclusive


def carrier_sections(captured: dict[str, Any], profile_id: str) -> tuple[
        dict[str, Any], dict[str, Any], list[Any], dict[str, Any]]:
    priming = captured.get("priming_get")
    connect = captured.get("extended_connect")
    assets = captured.get("asset_sequence")
    shaping = captured.get("shaping_policy")
    require(isinstance(priming, dict) and isinstance(connect, dict) and
            isinstance(assets, list) and len(assets) == 2 and
            isinstance(shaping, dict),
            f"{profile_id} H2 profile sections or asset geometry are invalid")
    require(integer(priming.get("stream_id"), f"{profile_id}.priming.stream_id",
                    minimum=1, maximum=0x7FFFFFFF) == 1,
            f"{profile_id} priming stream must be 1")
    require(integer(connect.get("stream_id"), f"{profile_id}.connect.stream_id",
                    minimum=1, maximum=0x7FFFFFFF) == 7,
            f"{profile_id} extended CONNECT stream must be 7")
    for asset_index, asset in enumerate(assets):
        require(isinstance(asset, dict),
                f"{profile_id}.assets[{asset_index}] must be an object")
        stream = integer(asset.get("stream_id"),
                         f"{profile_id}.assets[{asset_index}].stream_id",
                         minimum=1, maximum=0x7FFFFFFF)
        require(stream == 3 + 2 * asset_index,
                f"{profile_id}.assets[{asset_index}] must use stream {3 + 2 * asset_index}")
    return priming, connect, assets, shaping


def source_for(name: str, value: str, identity: dict[str, str]) -> tuple[str, str]:
    fixed = {
        "<cover-authority>": "Authority",
        "<authenticated-carrier-path>": "CarrierPath",
        "https://<cover-authority>": "Origin",
        "https://<cover-authority>/": "RootReferer",
    }
    if value in fixed:
        return fixed[value], ""
    dynamic = {
        ("user-agent", identity["user_agent"]): "UserAgent",
        ("sec-ch-ua", identity["client_hint_brand"]): "ClientHintBrand",
        ("sec-ch-ua-mobile", identity["client_hint_mobile"]): "ClientHintMobile",
        ("sec-ch-ua-platform", identity["client_hint_platform"]): "ClientHintPlatform",
    }
    selected = dynamic.get((name, value))
    return (selected, "") if selected is not None else ("Literal", value)


def hex16(value: Any, field: str) -> int:
    """Parse a '0xNNNN' IANA code point from the registry."""
    require(isinstance(value, str) and HEX16_RE.fullmatch(value) is not None,
            f"{field} must be a 0xNNNN string, got {value!r}")
    return int(value, 16)


def code_point_list(value: Any, field: str, *, maximum: int = 64) -> list[int]:
    require(isinstance(value, list) and 1 <= len(value) <= maximum,
            f"{field} must contain 1..{maximum} entries")
    parsed = [hex16(item, f"{field}[{i}]") for i, item in enumerate(value)]
    require(len(set(parsed)) == len(parsed), f"{field} contains duplicates")
    return parsed


def captured_client_hello(path: pathlib.Path, profile_id: str) -> dict[str, list[str]]:
    """The real browser ClientHello recorded in the committed capture.

    Only the fields the OpenSSL diagnostic backend can express are extracted.
    GREASE entries are dropped: their exact code points are runtime
    randomisation, not part of a selection policy.
    """
    document = read_json(path)
    hello = document.get("client_hello")
    require(isinstance(hello, dict), f"{profile_id}: capture has no client_hello")
    structured = hello.get("structured_extensions")
    require(isinstance(structured, dict),
            f"{profile_id}: capture has no structured_extensions")

    def without_grease(values: Any, field: str) -> list[str]:
        require(isinstance(values, list), f"{profile_id}.{field} must be a list")
        return [v.lower() for v in values
                if isinstance(v, str) and v != "GREASE"]

    def extension(code: str, key: str) -> list[str]:
        block = structured.get(code)
        require(isinstance(block, dict), f"{profile_id}: capture lacks extension {code}")
        return without_grease(block.get(key), f"capture.{code}.{key}")

    return {
        "cipher_suites": without_grease(hello.get("cipher_suites"), "cipher_suites"),
        "extensions": without_grease(hello.get("middle_extension_types"),
                                     "middle_extension_types"),
        "supported_groups": extension("0x000a", "values"),
        "signature_algorithms": extension("0x000d", "values"),
    }


# draft-ietf-tls-esni outer ECHClientHello fixed overhead: 1 type + 2 KDF +
# 2 AEAD + 1 config_id + 2 enc length + 32 X25519 enc + 2 payload length.
ECH_OUTER_OVERHEAD = 42

INJECTED_PAYLOADS = {
    "empty": "Empty",
    "alps": "Alps",
    "grease_ech": "GreaseEch",
    "grease_empty": "GreaseEmpty",
    "grease_one_byte": "GreaseOneByte",
}


def injected_extensions(selection: dict[str, Any],
                        profile_id: str) -> list[tuple[int, str]]:
    """Extensions OpenSSL will not emit itself, injected via add_custom_ext.

    A "GREASE" type emits 0, which the C++ side reads as "allocate an RFC 8701
    value when configuring the SSL_CTX" rather than a registry-fixed number.
    """
    field = f"{profile_id}.openssl_selection.injected_extensions"
    entries = selection.get("injected_extensions", [])
    require(isinstance(entries, list) and len(entries) <= 16,
            f"{field} must contain 0..16 entries")
    rows: list[tuple[int, str]] = []
    for item in entries:
        require(isinstance(item, dict), f"{field} entries must be objects")
        raw = item.get("type")
        require(isinstance(raw, str), f"{field}.type must be a string")
        kind = item.get("payload")
        require(kind in INJECTED_PAYLOADS,
                f"{field}.payload must be one of {sorted(INJECTED_PAYLOADS)}")
        rows.append((0 if raw == "GREASE" else hex16(raw, f"{field}.type"),
                     INJECTED_PAYLOADS[kind]))
    return rows


def check_tls_divergence(entry: dict[str, Any], selection: dict[str, Any],
                         capture: dict[str, list[str]], profile_id: str) -> None:
    """Pin the accepted gap between the diagnostic selection and the capture.

    The openssl-diagnostic backend deliberately does not reproduce the captured
    ClientHello. Its non-GREASE sets are closed, but stock OpenSSL cannot express
    the browser's GREASE geometry, per-connection extension permutation, or
    uncompressed-only EC point formats. That gap is allowed, but it must stay
    exactly what the registry declares. If either side drifts (the capture is
    refreshed, or someone edits a selection list), this fails and forces a
    conscious decision instead of silently widening a classifier-visible
    difference.

    Ordering is intentionally NOT compared by these set checks; it is covered
    separately by the diagnostic and patched-backend emitted-byte gates.
    """
    declared = entry.get("known_tls_divergence")
    require(isinstance(declared, dict),
            f"{profile_id}.known_tls_divergence must be an object")
    for field in ("cipher_suites", "supported_groups",
                  "signature_algorithms", "extensions"):
        offered = [v.lower() for v in selection[field]]
        recorded = capture[field]
        actual = {
            "missing": [v for v in recorded if v not in offered],
            "extra": [v for v in offered if v not in recorded],
        }
        expected = declared.get(field)
        require(isinstance(expected, dict),
                f"{profile_id}.known_tls_divergence.{field} must be an object")
        for side in ("missing", "extra"):
            want = expected.get(side)
            require(isinstance(want, list),
                    f"{profile_id}.known_tls_divergence.{field}.{side} must be a list")
            got = actual[side]
            require([v.lower() for v in want] == got,
                    f"{profile_id}: TLS divergence drift in {field}.{side}: "
                    f"registry declares {want}, capture vs selection gives {got}")


def emit_code_point_array(lines: list[str], symbol: str, values: list[int],
                          kind: str = "std::uint16_t") -> None:
    lines.append(f"constexpr std::array<{kind}, {len(values)}> {symbol}{{")
    body = ", ".join(f"0x{v:04x}" if kind == "std::uint16_t" else str(v)
                     for v in values)
    lines.append(f"    {body},")
    lines.append("};")
    lines.append("")


def emit_header_array(lines: list[str], symbol: str,
                      values: list[tuple[str, str]], identity: dict[str, str]) -> None:
    lines.append(f"constexpr std::array<HeaderTemplate, {len(values)}> {symbol}{{")
    for name, value in values:
        source, literal = source_for(name, value, identity)
        lines.append(
            f"    HeaderTemplate{{{cpp_string(name)}, Source::{source}, {cpp_string(literal)}}},")
    lines.append("};")
    lines.append("")


def emit_profile(entry: dict[str, Any], index: int,
                 ids: set[str], aliases: set[str],
                 helper_ids: set[str]) -> tuple[list[str], str]:
    profile_id = text(entry.get("id"), f"profiles[{index}].id", maximum=64)
    require(PROFILE_ID_RE.fullmatch(profile_id) is not None,
            f"invalid profile id: {profile_id}")
    alias = text(entry.get("client_alias"), f"{profile_id}.client_alias", maximum=32)
    require(ALIAS_RE.fullmatch(alias) is not None, f"invalid client alias: {alias}")
    require(profile_id not in ids, f"duplicate profile id: {profile_id}")
    require(alias not in aliases, f"duplicate client alias: {alias}")
    ids.add(profile_id)
    aliases.add(alias)
    declared_helper_build_id = text(entry.get("helper_build_id"),
                                    f"{profile_id}.helper_build_id", maximum=256)
    require(declared_helper_build_id not in helper_ids,
            f"duplicate helper build ID: {declared_helper_build_id}")
    helper_ids.add(declared_helper_build_id)

    fixture = fixture_path(entry.get("fixture"), profile_id)
    artifacts = profile_artifacts(entry, fixture, profile_id)
    manifest = read_json(artifacts["manifest"])
    captured = read_json(artifacts["http2_profile"])
    require(isinstance(manifest, dict) and manifest.get("schema") == 2,
            f"{profile_id} manifest schema must be 2")
    require(manifest.get("profile_id") == profile_id,
            f"{profile_id} does not match its manifest profile_id")
    require(isinstance(captured, dict) and captured.get("schema") == 2,
            f"{profile_id} H2 profile schema must be 2")

    browser = manifest.get("client")
    server = manifest.get("server")
    helper = manifest.get("helper_wire_qualification")
    require(isinstance(browser, dict) and isinstance(server, dict) and
            isinstance(helper, dict), f"{profile_id} manifest sections are incomplete")
    helper_build_id = text(helper.get("helper_build_id"),
                           f"{profile_id}.helper_build_id", maximum=256)
    require(helper_build_id == declared_helper_build_id,
            f"{profile_id} helper build ID does not match its manifest")
    helper_provider = text(entry.get("helper_provider"),
                           f"{profile_id}.helper_provider", maximum=64)
    require(helper_provider in HELPER_PROVIDERS,
            f"unsupported helper provider: {helper_provider}")

    priming, connect, assets, shaping = carrier_sections(captured, profile_id)

    priming_headers = headers(priming.get("headers_in_order"), f"{profile_id}.priming")
    connect_headers = headers(connect.get("headers_in_order"), f"{profile_id}.connect")
    identity = {
        "user_agent": header_value(priming_headers, "user-agent", f"{profile_id}.priming"),
        "client_hint_brand": header_value(priming_headers, "sec-ch-ua", f"{profile_id}.priming"),
        "client_hint_mobile": header_value(priming_headers, "sec-ch-ua-mobile", f"{profile_id}.priming"),
        "client_hint_platform": header_value(priming_headers, "sec-ch-ua-platform", f"{profile_id}.priming"),
    }

    tls_mapping = {
        "chrome151": "tls_fingerprint::BrowserProfile::CHROME_151",
        "unknown": "tls_fingerprint::BrowserProfile::UNKNOWN",
    }
    openssl_profile = text(entry.get("openssl_profile"),
                           f"{profile_id}.openssl_profile", maximum=32)
    require(openssl_profile in tls_mapping,
            f"unsupported OpenSSL profile selector: {openssl_profile}")

    prefix = f"kProfile{index}"
    lines: list[str] = []
    client_settings = setting_rows(captured.get("client_settings_in_order"),
                                   f"{profile_id}.client_settings")
    server_settings = setting_rows(captured.get("node_non_default_settings_in_order"),
                                   f"{profile_id}.server_settings")
    lines.append(
        f"constexpr std::array<H2Setting, {len(client_settings)}> {prefix}ClientSettings{{")
    lines.extend(f"    H2Setting{{{setting_id}U, {value}U}},"
                 for setting_id, value in client_settings)
    lines.extend(["};", ""])
    lines.append(
        f"constexpr std::array<H2Setting, {len(server_settings)}> {prefix}ServerSettings{{")
    lines.extend(f"    H2Setting{{{setting_id}U, {value}U}},"
                 for setting_id, value in server_settings)
    lines.extend(["};", ""])

    emit_header_array(lines, f"{prefix}PrimingHeaders", priming_headers, identity)
    emit_header_array(lines, f"{prefix}ConnectHeaders", connect_headers, identity)

    asset_records: list[tuple[str, str, tuple[int, int, bool]]] = []
    previous_stream: int | None = None
    for asset_index, asset in enumerate(assets):
        asset_path = text(asset.get("path"), f"{profile_id}.assets[{asset_index}].path", maximum=2048)
        asset_headers = headers(asset.get("headers_in_order"),
                                f"{profile_id}.assets[{asset_index}].headers")
        require(header_value(asset_headers, ":path",
                             f"{profile_id}.assets[{asset_index}].headers") == asset_path,
                f"{profile_id}.assets[{asset_index}] path/header mismatch")
        stream = integer(asset.get("stream_id"), f"{profile_id}.assets[{asset_index}].stream_id",
                         minimum=1, maximum=0x7FFFFFFF)
        captured_parent = integer(asset.get("parent_stream_id"),
                                  f"{profile_id}.assets[{asset_index}].parent_stream_id",
                                  maximum=0x7FFFFFFF)
        parent = -1 if previous_stream is not None and captured_parent == previous_stream else captured_parent
        prio = priority(asset, f"{profile_id}.assets[{asset_index}]", parent_override=parent)
        symbol = f"{prefix}Asset{asset_index}Headers"
        emit_header_array(lines, symbol, asset_headers, identity)
        asset_records.append((asset_path, symbol, prio))
        previous_stream = stream

    lines.append(
        f"constexpr std::array<AssetTemplate, {len(asset_records)}> {prefix}Assets{{")
    for asset_path, symbol, (parent, weight, exclusive) in asset_records:
        lines.append(
            f"    AssetTemplate{{{cpp_string(asset_path)}, RequestTemplate{{{symbol}, "
            f"H2Priority{{{parent}, {weight}, {str(exclusive).lower()}}}}}}},")
    lines.extend(["};", ""])

    priming_priority = priority(priming, f"{profile_id}.priming")
    connect_priority = priority(connect, f"{profile_id}.connect")
    window = captured.get("client_connection_window_update")
    require(isinstance(window, dict), f"{profile_id}.client_connection_window_update missing")
    window_delta = integer(window.get("delta"), f"{profile_id}.connection_window_update")
    websocket_bytes = integer(shaping.get("bulk_websocket_message_bytes"),
                              f"{profile_id}.websocket_message_bytes", minimum=1,
                              maximum=16 * 1024 * 1024)

    # TLS selection policy for the openssl-diagnostic backend. It used to be
    # free literals inside tls_fingerprint.cpp, keyed only by the BrowserProfile
    # enum, with nothing binding it to the committed capture. It now lives in
    # the registry, is generated into the profile alongside the H2 geometry, and
    # its gap against the capture is pinned below.
    selection = entry.get("openssl_selection")
    require(isinstance(selection, dict),
            f"{profile_id}.openssl_selection must be an object")
    tls_ciphers = code_point_list(selection.get("cipher_suites"),
                                  f"{profile_id}.openssl_selection.cipher_suites")
    tls_extensions = code_point_list(selection.get("extensions"),
                                     f"{profile_id}.openssl_selection.extensions")
    tls_groups = code_point_list(selection.get("supported_groups"),
                                 f"{profile_id}.openssl_selection.supported_groups")
    # OpenSSL emits a key_share only for groups whose name carries a "*" prefix
    # in SSL_CTX_set1_groups_list, and by default that is the first group alone.
    # A browser that offers a hybrid *and* a classical share needs both named
    # here. Every entry must appear in supported_groups: offering a share for a
    # group that is not advertised is a ClientHello no browser sends.
    tls_key_share_groups = code_point_list(
        selection.get("key_share_groups"),
        f"{profile_id}.openssl_selection.key_share_groups")
    for group in tls_key_share_groups:
        require(group in tls_groups,
                f"{profile_id}.openssl_selection.key_share_groups: "
                f"0x{group:04x} is not in supported_groups")
    require(len(set(tls_key_share_groups)) == len(tls_key_share_groups),
            f"{profile_id}.openssl_selection.key_share_groups must not repeat")
    tls_sigalgs = code_point_list(selection.get("signature_algorithms"),
                                  f"{profile_id}.openssl_selection.signature_algorithms")
    # RFC 8879 certificate compression. OpenSSL can only offer an algorithm it
    # was compiled with, so this is a request the build may not be able to
    # honour; tls_stealth.cpp reports the shortfall rather than failing.
    cert_comp_ids = {"zlib": 1, "brotli": 2, "zstd": 3}
    cert_comp = selection.get("cert_compression", [])
    require(isinstance(cert_comp, list) and len(cert_comp) <= 3,
            f"{profile_id}.openssl_selection.cert_compression must contain 0..3 entries")
    for name in cert_comp:
        require(name in cert_comp_ids,
                f"{profile_id}.openssl_selection.cert_compression: unknown "
                f"algorithm {name!r}; expected one of {sorted(cert_comp_ids)}")
    require(len(set(cert_comp)) == len(cert_comp),
            f"{profile_id}.openssl_selection.cert_compression must not repeat")
    tls_cert_comp = [cert_comp_ids[name] for name in cert_comp]

    point_formats = selection.get("ec_point_formats")
    require(isinstance(point_formats, list) and 1 <= len(point_formats) <= 8,
            f"{profile_id}.openssl_selection.ec_point_formats must contain 1..8 entries")
    tls_point_formats = [integer(v, f"{profile_id}.openssl_selection.ec_point_formats",
                                 maximum=255) for v in point_formats]
    alpn = selection.get("alpn_protocols")
    require(isinstance(alpn, list) and 1 <= len(alpn) <= 8,
            f"{profile_id}.openssl_selection.alpn_protocols must contain 1..8 entries")
    tls_alpn = [text(v, f"{profile_id}.openssl_selection.alpn_protocols", maximum=32)
                for v in alpn]
    # Offered version range, and the version the handshake is required to end
    # on. Chrome offers TLS 1.2 and 1.3; offering only 1.3 silently drops the
    # TLS 1.2 half of the cipher list and extension 0xff01. Requiring 1.3 as the
    # negotiated result keeps the ClientHello browser-shaped without accepting a
    # downgrade on the carrier.
    tls_min_version = hex16(selection.get("min_version", "0x0303"),
                            f"{profile_id}.openssl_selection.min_version")
    tls_max_version = hex16(selection.get("max_version", "0x0304"),
                            f"{profile_id}.openssl_selection.max_version")
    require_raw = selection.get("require_negotiated_version", "")
    tls_require_version = (hex16(require_raw,
                                 f"{profile_id}.openssl_selection."
                                 "require_negotiated_version")
                           if require_raw else 0)
    require(tls_min_version <= tls_max_version,
            f"{profile_id}.openssl_selection: min_version exceeds max_version")
    require(tls_require_version == 0 or
            tls_min_version <= tls_require_version <= tls_max_version,
            f"{profile_id}.openssl_selection: require_negotiated_version "
            "must lie inside the offered range")
    tls_injected = injected_extensions(selection, profile_id)
    alps = selection.get("alps_protocols", [])
    require(isinstance(alps, list) and len(alps) <= 8,
            f"{profile_id}.openssl_selection.alps_protocols must contain 0..8 entries")
    tls_alps = [text(v, f"{profile_id}.openssl_selection.alps_protocols", maximum=32)
                for v in alps]
    ech_lengths = selection.get("ech_grease_lengths", [])
    require(isinstance(ech_lengths, list) and len(ech_lengths) <= 16,
            f"{profile_id}.openssl_selection.ech_grease_lengths must contain 0..16 entries")
    tls_ech_lengths = [
        integer(v, f"{profile_id}.openssl_selection.ech_grease_lengths",
                minimum=ECH_OUTER_OVERHEAD + 1, maximum=4096)
        for v in ech_lengths]
    no_etm = selection.get("no_encrypt_then_mac", False)
    require(isinstance(no_etm, bool),
            f"{profile_id}.openssl_selection.no_encrypt_then_mac must be a boolean")
    status_request = selection.get("status_request", "")
    require(status_request in ("", "ocsp"),
            f"{profile_id}.openssl_selection.status_request must be \"ocsp\" or absent")

    check_tls_divergence(
        entry,
        {
            "cipher_suites": selection["cipher_suites"],
            "extensions": selection["extensions"],
            "supported_groups": selection["supported_groups"],
            "signature_algorithms": selection["signature_algorithms"],
        },
        captured_client_hello(artifacts["tls_wire_profile"], profile_id),
        profile_id)

    emit_code_point_array(lines, f"{prefix}TlsCiphers", tls_ciphers)
    emit_code_point_array(lines, f"{prefix}TlsExtensions", tls_extensions)
    emit_code_point_array(lines, f"{prefix}TlsGroups", tls_groups)
    emit_code_point_array(lines, f"{prefix}TlsKeyShareGroups", tls_key_share_groups)
    emit_code_point_array(lines, f"{prefix}TlsSigAlgs", tls_sigalgs)
    emit_code_point_array(lines, f"{prefix}TlsPointFormats", tls_point_formats,
                          kind="std::uint8_t")
    emit_code_point_array(lines, f"{prefix}TlsCertCompression", tls_cert_comp,
                          kind="std::uint16_t")
    emit_code_point_array(lines, f"{prefix}TlsEchGreaseLengths", tls_ech_lengths)
    lines.append(
        f"constexpr std::array<InjectedExtension, {len(tls_injected)}> "
        f"{prefix}TlsInjectedExtensions{{{{")
    for ext_type, payload in tls_injected:
        lines.append(f"    InjectedExtension{{0x{ext_type:04x}, "
                     f"InjectedExtensionPayload::{payload}}},")
    lines.append("}};")
    lines.append(
        f"constexpr std::array<std::string_view, {len(tls_alps)}> "
        f"{prefix}TlsAlpsProtocols{{{{")
    for proto in tls_alps:
        lines.append(f"    {cpp_string(proto)},")
    lines.append("}};")
    lines.append(f"constexpr std::array<std::string_view, {len(tls_alpn)}> "
                 f"{prefix}TlsAlpn{{")
    lines.append("    " + ", ".join(cpp_string(v) for v in tls_alpn) + ",")
    lines.append("};")
    lines.append("")

    def priority_cpp(value: tuple[int, int, bool]) -> str:
        parent, weight, exclusive = value
        return f"H2Priority{{{parent}, {weight}, {str(exclusive).lower()}}}"

    profile_symbol = f"{prefix}Value"
    values = [
        profile_id,
        alias,
        text(entry.get("tls_backend"), f"{profile_id}.tls_backend", maximum=64),
        helper_build_id,
        text(browser.get("browser"), f"{profile_id}.browser", maximum=128),
        text(browser.get("version"), f"{profile_id}.browser_version", maximum=128),
        text(browser.get("os"), f"{profile_id}.os", maximum=256),
        identity["user_agent"], identity["client_hint_brand"],
        identity["client_hint_mobile"], identity["client_hint_platform"],
    ]
    lines.append(f"const Profile {profile_symbol}{{")
    lines.extend(f"    {cpp_string(value)}," for value in values)
    lines.append(f"    {tls_mapping[openssl_profile]},")
    lines.extend([
        f"    0x{tls_min_version:04x},",
        f"    0x{tls_max_version:04x},",
        f"    0x{tls_require_version:04x},",
        f"    {prefix}TlsCiphers,",
        f"    {prefix}TlsExtensions,",
        f"    {prefix}TlsGroups,",
        f"    {prefix}TlsKeyShareGroups,",
        f"    {prefix}TlsSigAlgs,",
        f"    {prefix}TlsPointFormats,",
        f"    {prefix}TlsCertCompression,",
        f"    {prefix}TlsAlpn,",
        f"    {prefix}TlsInjectedExtensions,",
        f"    {prefix}TlsAlpsProtocols,",
        f"    {prefix}TlsEchGreaseLengths,",
        f"    {'true' if no_etm else 'false'},",
        f"    {'true' if status_request == 'ocsp' else 'false'},",
        f"    {cpp_string(text(server.get('runtime'), f'{profile_id}.server.runtime', maximum=128))},",
        f"    {cpp_string(text(server.get('version'), f'{profile_id}.server.version', maximum=128))},",
        f"    {prefix}ClientSettings,",
        f"    {prefix}ServerSettings,",
        f"    {window_delta}U,",
        f"    RequestTemplate{{{prefix}PrimingHeaders, {priority_cpp(priming_priority)}}},",
        f"    RequestTemplate{{{prefix}ConnectHeaders, {priority_cpp(connect_priority)}}},",
        f"    {prefix}Assets,",
        f"    {websocket_bytes}U,",
        "};",
        "",
    ])
    return lines, profile_symbol


def generate(registry_path: pathlib.Path,
             evidence_profile_id: str | None = None) -> str:
    registry = read_json(registry_path)
    require(isinstance(registry, dict) and registry.get("schema") == 1,
            "transport profile registry schema must be 1")
    entries = registry.get("profiles")
    require(isinstance(entries, list) and 1 <= len(entries) <= 32,
            "transport profile registry must contain 1..32 profiles")
    active = text(registry.get("active_profile"), "active_profile", maximum=64)

    lines = [
        "/* Generated by scripts/generate_transport_profiles.py. Do not edit. */",
        "namespace generated_profiles {",
        "",
        "using Source = HeaderValueSource;",
        "",
    ]
    ids: set[str] = set()
    aliases: set[str] = set()
    helper_ids: set[str] = set()
    symbols: list[str] = []
    for index, entry in enumerate(entries):
        require(isinstance(entry, dict), f"profiles[{index}] must be an object")
        emitted, symbol = emit_profile(entry, index, ids, aliases, helper_ids)
        lines.extend(emitted)
        symbols.append(symbol)
    require(active in ids, "active_profile does not name a registered profile")
    expected_active = (evidence_profile_id if evidence_profile_id is not None
                       else evidence_profile())
    require(active == expected_active,
            "active_profile must equal kEvidenceProfile")
    lines.append(
        f"inline constexpr std::string_view kActiveProfileId = {cpp_string(active)};")
    lines.append("")
    lines.append(f"const std::array<Profile, {len(symbols)}> kProfiles{{")
    lines.extend(f"    {symbol}," for symbol in symbols)
    lines.extend(["};", "", "}  // namespace generated_profiles", ""])
    return "\n".join(lines)


def generate_go(registry_path: pathlib.Path,
                evidence_profile_id: str | None = None) -> str:
    # Reuse all evidence, uniqueness, and active-profile validation before
    # emitting helper routing metadata.
    generate(registry_path, evidence_profile_id)
    registry = read_json(registry_path)
    lines = [
        "// Code generated by scripts/generate_transport_profiles.py. DO NOT EDIT.",
        "",
        "package main",
        "",
        "var clientHelloProfiles = []clientHelloProfile{",
    ]
    active_helper_build_id = ""
    for entry in registry["profiles"]:
        profile_id = entry["id"]
        fixture = fixture_path(entry["fixture"], profile_id)
        artifacts = profile_artifacts(entry, fixture, profile_id)
        manifest = read_json(artifacts["manifest"])
        helper_build_id = entry["helper_build_id"]
        if profile_id == registry["active_profile"]:
            active_helper_build_id = helper_build_id
        provider = entry["helper_provider"]
        function_name, display_name = HELPER_PROVIDERS[provider]
        lines.extend([
            "\t{",
            f"\t\tprofileID:   {json.dumps(profile_id)},",
            f"\t\tbuildID:     {json.dumps(helper_build_id)},",
            f"\t\tdisplayName: {json.dumps(display_name)},",
            f"\t\tbuildSpec:   {function_name},",
            "\t},",
        ])
    require(bool(active_helper_build_id),
            "active profile has no helper build identity")
    lines.extend([
        "}",
        "",
        f"const activeHelperBuildID = {json.dumps(active_helper_build_id)}",
        "",
    ])
    return "\n".join(lines)


def active_profile_metadata(
        registry_path: pathlib.Path = DEFAULT_REGISTRY,
        generated_path: pathlib.Path = DEFAULT_OUTPUT,
        go_generated_path: pathlib.Path = DEFAULT_GO_OUTPUT) -> dict[str, Any]:
    """Return validated release metadata for the active transport profile."""
    # Apply the complete bounded schema/evidence validation before exposing a
    # value to packaging or release tooling.
    generated = generate(registry_path)
    require(generated_path.is_file() and
            generated_path.read_text(encoding="utf-8") == generated,
            "generated C++ transport profiles are stale")
    go_generated = generate_go(registry_path)
    require(go_generated_path.is_file() and
            go_generated_path.read_text(encoding="utf-8") == go_generated,
            "generated Go transport profiles are stale")
    registry = read_json(registry_path)
    active_id = registry["active_profile"]
    entry = next(item for item in registry["profiles"] if item["id"] == active_id)
    fixture = fixture_path(entry["fixture"], active_id)
    artifacts = profile_artifacts(entry, fixture, active_id)
    manifest = read_json(artifacts["manifest"])
    return {
        "id": active_id,
        "client_alias": entry["client_alias"],
        "tls_backend": entry["tls_backend"],
        "fixture": fixture,
        "manifest": artifacts["manifest"],
        "http2_profile": artifacts["http2_profile"],
        "tls_wire_profile": artifacts["tls_wire_profile"],
        "tls_wire_candidates": artifacts["tls_wire_candidates"],
        "helper_build_id": manifest["helper_wire_qualification"]["helper_build_id"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=pathlib.Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--go-output", type=pathlib.Path, default=DEFAULT_GO_OUTPUT)
    parser.add_argument("--check", action="store_true",
                        help="fail if the checked-in generated file is stale")
    args = parser.parse_args()
    try:
        generated = generate(args.registry.resolve())
        go_generated = generate_go(args.registry.resolve())
        if args.check:
            current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
            require(current == generated,
                    f"generated C++ transport profiles are stale; run {pathlib.Path(__file__).name}")
            go_current = (args.go_output.read_text(encoding="utf-8")
                          if args.go_output.is_file() else "")
            require(go_current == go_generated,
                    f"generated Go transport profiles are stale; run {pathlib.Path(__file__).name}")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(generated, encoding="utf-8")
            args.go_output.parent.mkdir(parents=True, exist_ok=True)
            args.go_output.write_text(go_generated, encoding="utf-8")
    except (OSError, ProfileError) as error:
        print(f"transport profile generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
