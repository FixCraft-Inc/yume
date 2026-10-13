#!/usr/bin/env python3
"""Validate and generate YUME's shared desktop/Android message catalog.

The JSON catalog is the only hand-edited translation source. Qt TS and Kotlin
maps are generated views; generated files carry a banner and are reproducible.
"""
from __future__ import annotations
import argparse, html, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "translations/catalog.json"
ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z0-9]+)*$")
TAG_RE = re.compile(r"</?[A-Za-z][^>]*>")
TOKEN_RE = re.compile(r"%(?:\d+\$)?[-+# 0,(]*\d*(?:\.\d+)?[sdif]|%\d+")
DIRECT_QT_RE = re.compile(r"\bqsTr\s*\(|(?<![A-Za-z0-9_])tr\s*\(")
LANGS = ("ru", "ja", "uk")
QT_LANGS = ("en", "ru", "ja", "uk")

def catalog_languages(data: dict) -> tuple[str, ...]:
    value = data.get("maintained_languages", LANGS)
    return tuple(value) if isinstance(value, list) else LANGS

def qt_languages(data: dict) -> tuple[str, ...]:
    return ("en",) + catalog_languages(data)

def load(path: Path = CATALOG) -> dict:
    try: data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e: raise SystemExit(f"catalog: {e}")
    return data

def runtime_source_errors(root: Path = ROOT) -> list[str]:
    """Reject source-text lookups so the catalog ID is the runtime identity."""
    errors = []
    paths = list((root / "src/gui").glob("**/*.cpp"))
    paths += list((root / "src/gui").glob("**/*.hpp"))
    paths += list((root / "src/gui").glob("**/*.qml"))
    paths += list((root / "src/gui").glob("**/*.js"))
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8")
        for match in DIRECT_QT_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            errors.append(f"{path.relative_to(root)}:{line}: use qsTrId/qtTrId with a catalog ID")
    return errors

def validate(data: dict) -> list[str]:
    errors=[]; messages=data.get("messages")
    if data.get("version") != 1 or not isinstance(messages,list): return ["catalog must have version 1 and a messages array"]
    ids=set(); sources=set()
    for i,m in enumerate(messages):
        where=f"messages[{i}]"
        mid=m.get("id")
        if not isinstance(mid,str) or not ID_RE.fullmatch(mid): errors.append(f"{where}: invalid id {mid!r}")
        elif mid in ids: errors.append(f"{where}: duplicate id {mid}")
        ids.add(mid)
        source=m.get("source")
        if isinstance(source,str) and source in sources: errors.append(f"{where}: duplicate source text; assign one stable ID")
        sources.add(source)
        for key in ("source","context","owner","notes"):
            if not isinstance(m.get(key),str) or not m[key].strip(): errors.append(f"{where}.{key}: required non-empty string")
        requirements=m.get("requirements",{})
        expected=requirements.get("placeholders",[])
        limit=requirements.get("character_limit")
        if limit is not None and (not isinstance(limit,int) or limit < 1): errors.append(f"{where}: character_limit must be a positive integer")
        if isinstance(limit,int) and len(m.get("source","")) > limit: errors.append(f"{where}: source exceeds character_limit")
        actual=TOKEN_RE.findall(m.get("source",""))
        if expected != actual: errors.append(f"{where}: requirements.placeholders {expected!r} != source {actual!r}")
        translations=m.get("translations")
        if not isinstance(translations,dict): errors.append(f"{where}.translations: object required"); continue
        for lang in catalog_languages(data):
            value=translations.get(lang)
            if not isinstance(value,str) or not value.strip(): errors.append(f"{where}: missing {lang} translation")
            elif sorted(TOKEN_RE.findall(value)) != sorted(actual): errors.append(f"{where}: {lang} placeholders {TOKEN_RE.findall(value)!r} != {actual!r}")
            if isinstance(value, str) and (value.count("<") != value.count(">") or TAG_RE.findall(value) != TAG_RE.findall(m.get("source", ""))):
                errors.append(f"{where}: {lang} malformed or changed markup")
        for term in data.get("terminology", []):
            if term in m.get("source", ""):
                for lang, value in translations.items():
                    if lang in catalog_languages(data) and term not in value:
                        errors.append(f"{where}: {lang} drops protected term {term}")
        for lang,value in translations.items():
            if lang in catalog_languages(data) and value == m.get("source") and not m.get("language_neutral"):
                errors.append(f"{where}: {lang} is an English fallback; mark language_neutral only for intentional terms")
    return errors

def kotlin(s: str) -> str:
    return json.dumps(s,ensure_ascii=False).replace("$", "\\$")

def message_symbol(mid: str) -> str:
    return mid.replace(".", "_").upper()


def android_source_errors(data: dict, android_root: Path) -> list[str]:
    path = android_root / "app/src/main/java/com/fixcraft/yume/i18n/AppStrings.kt"
    text = path.read_text(encoding="utf-8")
    known = {message_symbol(m["id"]) for m in data["messages"]}
    used = set(re.findall(r"MessageId\.([A-Z0-9_]+)", text))
    errors = [f"unknown Android message ID accessor: {name}" for name in sorted(used - known)]
    if re.search(r'\bt\(\s*"', text) or "sourceToId" in text:
        errors.append("AppStrings must use typed message IDs, not English lookup keys")
    return errors


def generate_android(data: dict, out: Path) -> None:
    out.mkdir(parents=True,exist_ok=True)
    maps = out / "translations"
    maps.mkdir(parents=True,exist_ok=True)
    for lang in catalog_languages(data):
        lines=["// GENERATED by scripts/yume_translations.py; do not edit.","package com.fixcraft.yume.i18n.translations","","import com.fixcraft.yume.i18n.LanguageBundle","","internal object Language%s : LanguageBundle {" % lang.title(),f'    override val localeTag: String = "{lang}"',"    override val translations: Map<String, String> = linkedMapOf("]
        for m in data["messages"]: lines.append(f"        {kotlin(m['id'])} to {kotlin(m['translations'][lang])},")
        lines += ["    )","}",""]
        (maps/f"Language{lang.title()}.kt").write_text("\n".join(lines),encoding="utf-8")
    lines=["// GENERATED by scripts/yume_translations.py; do not edit.","package com.fixcraft.yume.i18n","","/** Stable IDs and source text for the shared catalog. */","internal object TranslationCatalog {","    val sourceToId: Map<String, String> = linkedMapOf("]
    for m in data["messages"]: lines.append(f"        {kotlin(m['source'])} to {kotlin(m['id'])},")
    lines += ["    )", "    val idToSource: Map<String, String> = linkedMapOf("]
    for m in data["messages"]: lines.append(f"        {kotlin(m['id'])} to {kotlin(m['source'])},")
    lines += ["    )", "}", ""]
    lines += ["/** Generated message identities, independent of English copy. */",
              "enum class MessageId(val id: String, val source: String) {"]
    for m in data["messages"]:
        lines.append(f"    {message_symbol(m['id'])}({kotlin(m['id'])}, {kotlin(m['source'])}),")
    lines += ["}", ""]
    (out/"TranslationCatalog.kt").write_text("\n".join(lines),encoding="utf-8")

def qt_text(value: str) -> str:
    """Adapt printf/Kotlin placeholders to Qt's numbered %1 form."""
    index = 0
    def replace(match: re.Match[str]) -> str:
        nonlocal index
        token = match.group(0)
        if token.startswith("%") and token[1:].isdigit():
            return token
        numbered = re.fullmatch(r"%(\d+)\$[sdif]", token)
        if numbered:
            return "%" + numbered.group(1)
        index += 1
        return "%" + str(index)
    return re.sub(r"%(?:\d+\$)?[-+# 0,(]*\d*(?:\.\d+)?[sdif]|%\d+", replace, value)

def generate_qt(data: dict, out: Path) -> None:
    out.mkdir(parents=True,exist_ok=True)
    for lang in qt_languages(data):
        lines=['<?xml version="1.0" encoding="utf-8"?>','<!DOCTYPE TS>','<!-- GENERATED by scripts/yume_translations.py; do not edit. -->',f'<TS version="2.1" language="{lang}">']
        # ID lookups use the empty context and source, matching the TS shape
        # emitted by lupdate for qtTrId/qsTrId. Keep richer metadata in an
        # extra comment for Linguist users without changing the lookup key.
        lines += ["  <context>", "    <name></name>"]
        for m in data["messages"]:
            translated = m["source"] if lang == "en" else m["translations"][lang]
            tr=html.escape(qt_text(translated),quote=False)
            note = html.escape(
                f"source: {m['source']}; context: {m['context']}; "
                f"owner: {m['owner']}; {m['notes']}",
                quote=False)
            lines += [f"    <message id=\"{m['id']}\">",f"      <location filename=\"catalog:{m['id']}\" line=\"1\"/>","      <source></source>",f"      <extracomment>{note}</extracomment>",f"      <translation>{tr}</translation>","    </message>"]
        lines += ["  </context>", "</TS>",""]
        (out/f"yume_{lang}.ts").write_text("\n".join(lines),encoding="utf-8")

def add(args):
    data=load(); errs=validate(data)
    if args.id in {m['id'] for m in data['messages']}: raise SystemExit(f"add: duplicate id {args.id}")
    placeholders=TOKEN_RE.findall(args.source)
    translations={l:"" for l in data['maintained_languages']}
    data['messages'].append({'id':args.id,'source':args.source,'context':args.context,'owner':args.owner,'notes':args.notes,'requirements':{'placeholders':placeholders},'translations':translations})
    CATALOG.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print(f"added {args.id}; fill translations, then run validate")

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='command',required=True)
    v=sub.add_parser('validate'); v.add_argument('--catalog',type=Path,default=CATALOG)
    a=sub.add_parser('add'); a.add_argument('id'); a.add_argument('source'); a.add_argument('--context',required=True); a.add_argument('--owner',required=True); a.add_argument('--notes',required=True)
    r=sub.add_parser('rename'); r.add_argument('old'); r.add_argument('new')
    g=sub.add_parser('generate'); g.add_argument('--android-root',type=Path); g.add_argument('--check',action='store_true')
    args=p.parse_args(); data=load()
    if args.command=='validate':
        errors=validate(load(args.catalog));
        if args.catalog == CATALOG:
            errors += runtime_source_errors()
        if errors: print("\n".join(errors),file=sys.stderr); return 1
        print(f"valid: {len(load(args.catalog)['messages'])} messages; maintained languages: {', '.join(LANGS)}"); return 0
    if args.command=='add': add(args); return 0
    if args.command=='rename':
        if any(m['id']==args.new for m in data['messages']): raise SystemExit(f"rename: duplicate id {args.new}")
        for m in data['messages']:
            if m['id']==args.old: m['id']=args.new; break
        else: raise SystemExit(f"rename: unknown id {args.old}")
        CATALOG.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n'); print(f"renamed {args.old} -> {args.new}"); return 0
    errors=validate(data)
    if errors: print("\n".join(errors),file=sys.stderr); return 1
    if args.check:
        # compare against temporary deterministic output without touching targets
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            generate_qt(data,Path(t)/"qt"); generate_android(data,Path(t)/"android")
            pairs=[(Path(t)/"qt"/f"yume_{l}.ts",ROOT/"src/gui/translations"/f"yume_{l}.ts") for l in qt_languages(data)]
            if args.android_root: pairs += [(Path(t)/"android/translations"/f"Language{l.title()}.kt",args.android_root/"app/src/main/java/com/fixcraft/yume/i18n/translations"/f"Language{l.title()}.kt") for l in catalog_languages(data)] + [(Path(t)/"android/TranslationCatalog.kt",args.android_root/"app/src/main/java/com/fixcraft/yume/i18n/TranslationCatalog.kt")]
            stale=[str(dst) for src,dst in pairs if not dst.is_file() or src.read_bytes()!=dst.read_bytes()]
            if stale:
                print("generated output is stale (regenerate; source IDs are canonical):\n"+"\n".join(stale),file=sys.stderr); return 1
    else:
        generate_qt(data,ROOT/"src/gui/translations")
        if args.android_root: generate_android(data,args.android_root/"app/src/main/java/com/fixcraft/yume/i18n")
    print(f"generated {len(data['messages'])} messages")
    return 0
if __name__=='__main__': raise SystemExit(main())
