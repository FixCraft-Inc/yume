#!/usr/bin/env python3
"""Drift and contract checks for the shared UI message catalog."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import argparse
import json

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("yume_translations", ROOT / "scripts/yume_translations.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

def with_community(data: dict, coverage: float = 1.0) -> dict:
    """A copy of the catalog with a synthetic German community language that
    translates the given share of the messages it may translate."""
    import copy
    changed = copy.deepcopy(data)
    changed["community_languages"] = {"de": {"name": "Deutsch", "since": "2026-10-13", "credits": [
        {"name": "Example Studio", "kind": "studio", "url": "https://example.org"},
        {"name": "A. Translator", "kind": "person"}]}}
    eligible = [m for m in changed["messages"] if not m.get("maintainer_review")]
    for m in eligible[:int(len(eligible) * coverage)]:
        if not m.get("language_neutral"):
            m["translations"]["de"] = m["translations"]["ru"]
    return changed


def check_community_languages(data: dict) -> None:
    reviewed = [m for m in data["messages"] if m.get("maintainer_review")]
    if not any(m["id"] == "desktop.accept.this.route" for m in reviewed):
        raise SystemExit("route consent must stay maintainer_review text")
    # ru text has ru terminology and placeholders, so it passes as German here.
    full = with_community(data)
    errors = mod.validate(full)
    if errors:
        raise SystemExit("a complete community language was refused:\n" + "\n".join(errors[:5]))
    if abs(mod.community_coverage(full, "de") - 1.0) > 1e-9:
        raise SystemExit("complete community coverage is not 100%")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        partial = with_community(data, 0.92)
        assert not mod.validate(partial)
        mod.generate_qt(partial, out / "qt")
        mod.generate_android(partial, out / "android")
        ts = (out / "qt/yume_de.ts").read_text()
        missing = next(m for m in partial["messages"] if not m.get("language_neutral") and "de" not in m["translations"])
        if f'id="{missing["id"]}"' in ts or 'id="desktop.accept.this.route"' in ts:
            raise SystemExit("untranslated or reviewed text entered the community catalog instead of English")
        listing = (out / "android/TranslationCredits.kt").read_text()
        percent = int(mod.community_coverage(partial, "de") * 100)
        if not 90 <= percent < 100:
            raise SystemExit(f"partial community coverage is {percent}%")
        for needed in (f'CommunityLanguage("de", "Deutsch", {percent},', 'TranslationCredit.Kind.Studio, "https://example.org"',
                       'TranslationCredit("A. Translator", TranslationCredit.Kind.Person, null)', '"de" to LanguageDe'):
            if needed not in listing:
                raise SystemExit(f"generated community listing lacks {needed}")
        desktop = {entry["tag"]: entry for entry in json.loads((out / "qt/translation_credits.json").read_text())["languages"]}
        if (desktop["de"]["coverage"] != percent or desktop["de"]["group"] != "community"
                or desktop["de"]["credits"][0]["kind"] != "studio"):
            raise SystemExit("desktop community listing differs from the catalog")
        if [desktop[tag]["group"] for tag in mod.catalog_languages(partial)] != ["maintained"] * 3:
            raise SystemExit("maintained languages are missing from the desktop credits")
        if '"ru" to listOf(TranslationCredit("FixCraft Inc.", TranslationCredit.Kind.Studio, null))' not in listing:
            raise SystemExit("maintained credits are missing from the Android listing")
        orphan = ROOT / "src/gui/translations/yume_de.ts"
        if not any(view == orphan for _, view in mod.generated_pairs(data, out, None)) and orphan.exists():
            raise SystemExit("a stale community view is not reported")

    def refused(change, needle: str) -> None:
        candidate = with_community(data)
        change(candidate)
        if not any(needle in error for error in mod.validate(candidate)):
            raise SystemExit(f"community catalog accepted a case that must fail: {needle}")
    refused(lambda d: [m for m in d["messages"] if m["id"] == "desktop.accept.this.route"][0]["translations"].update(de="Annehmen"),
            "cannot translate maintainer_review text")
    refused(lambda d: d["messages"][0]["translations"].update(xx="x"), "neither a maintained nor a community language")
    refused(lambda d: d["community_languages"]["de"]["credits"][0].update(url="http://example.org"), "an https URL")
    refused(lambda d: d["community_languages"]["de"].update(credits=[]), "at least one translator")
    refused(lambda d: d["community_languages"].update(ru=d["community_languages"]["de"]), "neither English nor maintained")
    refused(lambda d: d["maintained_language_details"]["ru"].update(credits=[]), "at least one translator")
    refused(lambda d: d["maintained_language_details"].pop("uk"), "cover exactly the maintained languages")
    refused(lambda d: [m for m in d["messages"] if m["id"] == "route.hops"][0]["translations"].update(de="Hops"), "placeholders")
    low = with_community(data, 0.5)
    if not any("below the 80% floor" in error for error in mod.validate(low)):
        raise SystemExit("a community language under the coverage floor was listed")


def check_desktop_preset_texts(data: dict) -> None:
    """The desktop maps each English text of the tuning table to the catalog
    message with that exact source (src/gui/qml/Labels.js). An edited table
    text or message must fail here instead of showing English or a stale
    translation."""
    import re
    labels = (ROOT / "src/gui/qml/Labels.js").read_text(encoding="utf-8")
    table = re.search(r"const presetMessages = \{(.*?)\n\}", labels, re.S)
    if not table:
        raise SystemExit("Labels.js has no presetMessages table")
    mapping = dict(re.findall(r'^\s*"((?:[^"\\]|\\.)*)": "([a-z0-9.]+)",?$', table.group(1), re.M))
    presets = json.loads((ROOT / "config/tuning_presets.json").read_text(encoding="utf-8"))
    shown = list(presets["levels"].values()) + [field["label"] for field in presets["fields"]]
    for measurement in presets["measurements"].values():
        shown += [measurement["metric"], measurement["conditions"], measurement["limitation"]]
    by_id = {m["id"]: m for m in data["messages"]}
    errors = [f"tuning text has no presetMessages entry: {text!r}" for text in shown if text not in mapping]
    for text, message_id in mapping.items():
        if text not in shown:
            errors.append(f"presetMessages entry is not in tuning_presets.json: {text!r}")
        elif by_id.get(message_id, {}).get("source") != text:
            errors.append(f"presetMessages maps {text!r} to {message_id}, whose source differs")
    if errors:
        raise SystemExit("desktop tuning texts drifted:\n" + "\n".join(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--android-root", type=Path)
    args = parser.parse_args()
    data = mod.load()
    errors = mod.validate(data)
    errors += mod.runtime_source_errors()
    if args.android_root:
        errors += mod.android_source_errors(data, args.android_root)
    if errors:
        raise SystemExit("translation catalog errors:\n" + "\n".join(errors))
    # Generate into a private directory and compare the checked-in desktop
    # views. This catches hand edits, missing IDs, and nondeterministic order.
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        mod.generate_qt(data, out)
        if (out / "translation_credits.json").read_bytes() != (ROOT / "src/gui/translations/translation_credits.json").read_bytes():
            raise SystemExit("stale generated desktop translation credits")
        for lang in mod.qt_languages(data):
            expected = out / f"yume_{lang}.ts"
            actual = ROOT / "src/gui/translations" / expected.name
            if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
                raise SystemExit(f"stale generated desktop catalog: {actual}")
            if "GENERATED by scripts/yume_translations.py; do not edit." not in actual.read_text():
                raise SystemExit(f"missing generated banner: {actual}")
    if args.android_root:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            mod.generate_android(data, out)
            for lang in mod.catalog_languages(data):
                expected = out / "translations" / f"Language{lang.title()}.kt"
                actual = args.android_root / "app/src/main/java/com/fixcraft/yume/i18n/translations" / expected.name
                if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
                    raise SystemExit(f"stale generated Android catalog: {actual}")
            expected = out / "TranslationCatalog.kt"
            actual = args.android_root / "app/src/main/java/com/fixcraft/yume/i18n/TranslationCatalog.kt"
            if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
                raise SystemExit(f"stale Android ID catalog: {actual}")

    # English edits keep typed identities stable; a removed ID must fail validation.
    import copy
    changed = copy.deepcopy(data)
    original_id = changed["messages"][0]["id"]
    changed["messages"][0]["source"] = "An edited English message"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        mod.generate_android(changed, out)
        generated = (out / "TranslationCatalog.kt").read_text()
        assert f'{mod.message_symbol(original_id)}("{original_id}", "An edited English message")' in generated
        fake = out / "app/src/main/java/com/fixcraft/yume/i18n"
        fake.mkdir(parents=True)
        (fake / "AppStrings.kt").write_text("val text = t(MessageId.REMOVED_ID)")
        assert mod.android_source_errors(data, out)
        (fake / "AppStrings.kt").write_text('val text = t("Back")')
        assert mod.android_source_errors(data, out)

    by_id = {m["id"]: m for m in data["messages"]}
    required = {"nav.back", "preparing.language", "posture.server.detail", "accessibility.copy.value", "route.hops"}
    missing = required - by_id.keys()
    if missing:
        raise SystemExit("representative catalog IDs missing: " + ", ".join(sorted(missing)))
    if not by_id["posture.server.detail"]["requirements"].get("multiline"):
        raise SystemExit("technical explanation must declare multiline formatting")
    if by_id["route.hops"]["requirements"].get("plural") != "count":
        raise SystemExit("count-sensitive route message must declare plural=count")

    check_community_languages(data)
    check_desktop_preset_texts(data)

    ids = [m["id"] for m in data["messages"]]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate IDs survived validation")
    print(f"translation catalog: {len(ids)} IDs, {len(mod.catalog_languages(data))} maintained languages, generated desktop and requested Android outputs match")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
