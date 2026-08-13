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


def authenticated_profile(path: pathlib.Path = DEFAULT_VERSION_HEADER) -> str:
    source = path.read_text(encoding="utf-8")
    matches = re.findall(r'kTransportProfile\s*=\s*"([^"]+)"', source)
    require(len(matches) == 1,
            f"expected exactly one kTransportProfile declaration in {path}")
    require(PROFILE_ID_RE.fullmatch(matches[0]) is not None,
            "authenticated transport profile has an invalid ID")
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
        "    0x0304,",
        "    0x0304,",
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
             authenticated_profile_id: str | None = None) -> str:
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
    expected_active = (authenticated_profile_id if authenticated_profile_id is not None
                       else authenticated_profile())
    require(active == expected_active,
            "active_profile must equal authenticated kTransportProfile")
    lines.append(
        f"inline constexpr std::string_view kActiveProfileId = {cpp_string(active)};")
    lines.append("")
    lines.append(f"const std::array<Profile, {len(symbols)}> kProfiles{{")
    lines.extend(f"    {symbol}," for symbol in symbols)
    lines.extend(["};", "", "}  // namespace generated_profiles", ""])
    return "\n".join(lines)


def generate_go(registry_path: pathlib.Path,
                authenticated_profile_id: str | None = None) -> str:
    # Reuse all evidence, uniqueness, and active-profile validation before
    # emitting helper routing metadata.
    generate(registry_path, authenticated_profile_id)
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
