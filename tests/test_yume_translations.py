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
        if [desktop[tag]["group"] for tag in mod.catalog_languages(partial)] != ["maintained"] * len(mod.catalog_languages(partial)):
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
    refused(lambda d: d["community_languages"].update(ru=d["community_languages"]["de"]), "already a maintained language")
    refused(lambda d: d["community_languages"].update(en=d["community_languages"].pop("de")), "and not English")
    refused(lambda d: d["maintained_language_details"]["ru"].update(credits=[]), "at least one translator")
    refused(lambda d: d["maintained_language_details"].pop("uk"), "cover exactly the maintained languages")
    refused(lambda d: [m for m in d["messages"] if m["id"] == "route.hops"][0]["translations"].update(de="Hops"), "placeholders")
    check_language_tags(data)
    low = with_community(data, 0.5)
    if not any("below the 80% floor" in error for error in mod.validate(low)):
        raise SystemExit("a community language under the coverage floor was listed")


def check_language_tags(data: dict) -> None:
    """A tag is a language code with an optional script subtag and no region,
    and Chinese names its script, since one catalog cannot serve readers of
    both. A script-tagged language generates under its own names."""
    import copy
    if "zh-Hans" not in mod.catalog_languages(data):
        raise SystemExit("Simplified Chinese is not a maintained language")
    for tag in ("zh", "zh-CN", "zh-hans", "zh-Hans-CN", "zh-Latn", "ZH", "deu-"):
        candidate = with_community(data)
        candidate["community_languages"][tag] = candidate["community_languages"].pop("de")
        for m in candidate["messages"]:
            if "de" in m["translations"]: m["translations"][tag] = m["translations"].pop("de")
        if not any(f"community_languages.{tag}:" in error for error in mod.validate(candidate)):
            raise SystemExit(f"community language tag {tag!r} was accepted")
    candidate = copy.deepcopy(data)
    candidate["maintained_languages"] = [("zh" if t == "zh-Hans" else t) for t in candidate["maintained_languages"]]
    candidate["maintained_language_details"]["zh"] = candidate["maintained_language_details"].pop("zh-Hans")
    for m in candidate["messages"]:
        m["translations"]["zh"] = m["translations"].pop("zh-Hans")
    if not any("zh must name its script" in error for error in mod.validate(candidate)):
        raise SystemExit("a maintained Chinese language without a script was accepted")
    traditional = with_community(data)
    traditional["community_languages"] = {"zh-Hant": traditional["community_languages"].pop("de")}
    for m in traditional["messages"]:
        if "de" in m["translations"]: m["translations"]["zh-Hant"] = m["translations"].pop("de")
    if errors := mod.validate(traditional):
        raise SystemExit("a Traditional Chinese community language was refused:\n" + "\n".join(errors[:5]))
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        mod.generate_qt(traditional, out / "qt")
        mod.generate_android(traditional, out / "android")
        if '<TS version="2.1" language="zh_Hans">' not in (out / "qt/yume_zh-Hans.ts").read_text():
            raise SystemExit("the zh-Hans TS file does not name its language the Qt way")
        if "internal object LanguageZhHans : LanguageBundle" not in (out / "android/translations/LanguageZhHans.kt").read_text():
            raise SystemExit("the zh-Hans Kotlin bundle is not named LanguageZhHans")
        if '"zh-Hant" to LanguageZhHant,' not in (out / "android/TranslationCredits.kt").read_text():
            raise SystemExit("a script-tagged community bundle is not listed")


def check_language_scripts(data: dict) -> None:
    """A maintained language contains no letter of a script it is not written
    in. Text pasted from the wrong language keeps its placeholders, so only
    this check refuses it."""
    import copy
    for lang, text in (("ja", "%1 Мбит/с"), ("ru", "%1 メガビット"), ("uk", "%1 兆"),
                       ("zh-Hans", "%1 メガビット/秒"), ("zh-Hans", "%1 Мбит/с")):
        candidate = copy.deepcopy(data)
        [m for m in candidate["messages"] if m["id"] == "desktop.mbit.s"][0]["translations"][lang] = text
        if not any(f"{lang} contains the" in error for error in mod.validate(candidate)):
            raise SystemExit(f"{lang} text in another language's script was accepted: {text!r}")


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


# Words a glossary term replaced (private TRANSLATION.md glossary), which a
# new draft would otherwise bring back.
REPLACED_TERMS = {
    "ru": {"комплект": "набор", "контур": "цепочка"},
    "uk": {"комплект": "набір", "контур": "ланцюжок", "open-source": "з відкритим кодом"},
}


def check_replaced_terms(data: dict) -> None:
    errors = []
    for message in data["messages"]:
        for lang, terms in REPLACED_TERMS.items():
            text = message.get("translations", {}).get(lang, "").lower()
            errors += [f"{message['id']} [{lang}]: {old!r}, the glossary says {new!r}"
                       for old, new in terms.items() if old in text]
    if errors:
        raise SystemExit("replaced glossary terms are back:\n" + "\n".join(errors))


def check_route_cost_texts(data: dict) -> None:
    """The route-consent dialog shows a shorter route's cost in the interface
    language by the code yume sends (src/runtime/circuit_status.hpp). Every
    runtime code needs a case in Labels.js routeCost(), each case's message
    must be maintainer_review text whose source is the runtime's English, and
    the dialog must not know a code the runtime does not send."""
    import re
    def literal(parts: str) -> str:
        return "".join(json.loads(f'"{part}"') for part in re.findall(r'"((?:[^"\\]|\\.)*)"', parts))
    def cases(function: str) -> dict[str, str]:
        body = re.search(rf"{function}\(ShorterRouteCost cost\) noexcept \{{(.*?)\n\}}", header, re.S)
        if not body:
            raise SystemExit(f"circuit_status.hpp has no {function}")
        return {name: literal(value) for name, value in
                re.findall(r"case ShorterRouteCost::(\w+):\s*return((?:\s*\"(?:[^\"\\]|\\.)*\")+);", body.group(1))}
    header = (ROOT / "src/runtime/circuit_status.hpp").read_text(encoding="utf-8")
    codes, texts = cases("shorter_route_cost_code"), cases("shorter_route_cost_text")
    enum = re.search(r"enum class ShorterRouteCost : std::uint8_t \{(.*?)\};", header, re.S)
    members = re.findall(r"^\s*(\w+),", enum.group(1), re.M) if enum else []
    errors = []
    if not members or set(codes) != set(members) or set(texts) != set(members):
        errors.append(f"every ShorterRouteCost needs a code and a text: {members} {sorted(codes)} {sorted(texts)}")
    labels = (ROOT / "src/gui/qml/Labels.js").read_text(encoding="utf-8")
    function = re.search(r"function routeCost\(proposal\) \{(.*?)\n\}", labels, re.S)
    shown = dict(re.findall(r'case "([a-z_]+)":\s*return qsTrId\("([a-z0-9.]+)"\)', function.group(1))) if function else {}
    by_id = {m["id"]: m for m in data["messages"]}
    for member, code in codes.items():
        message = by_id.get(shown.get(code, ""))
        if message is None:
            errors.append(f"Labels.js routeCost() does not translate {code}")
        elif message["source"] != texts.get(member):
            errors.append(f"{message['id']} source differs from the runtime's {code} text")
        elif not message.get("maintainer_review"):
            errors.append(f"{message['id']} must be maintainer_review text")
    errors += [f"Labels.js routeCost() maps {code}, which the runtime never sends"
               for code in shown if code not in codes.values()]
    if errors:
        raise SystemExit("route consent texts drifted:\n" + "\n".join(errors))


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
                expected = out / "translations" / f"Language{mod.language_symbol(lang)}.kt"
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
    check_language_scripts(data)
    check_desktop_preset_texts(data)
    check_route_cost_texts(data)
    check_replaced_terms(data)

    ids = [m["id"] for m in data["messages"]]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate IDs survived validation")
    print(f"translation catalog: {len(ids)} IDs, {len(mod.catalog_languages(data))} maintained languages, generated desktop and requested Android outputs match")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
