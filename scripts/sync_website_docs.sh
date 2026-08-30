#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
site_docs="${repo_root}/website/docs"

mkdir -p "${site_docs}"
rm -f "${site_docs}"/*.md
rm -rf "${site_docs}/protocol"

render_doc() {
    local source_path="$1"
    local output_path="$2"
    local permalink="$3"
    local title

    title="$(head -n 1 "${source_path}" | sed -E 's/^#[[:space:]]*//')"
    mkdir -p "$(dirname "${output_path}")"

    {
        printf '%s\n' '---'
        printf 'layout: doc\n'
        printf 'title: %s\n' "${title}"
        printf 'permalink: %s\n' "${permalink}"
        printf '%s\n\n' '---'
        sed -E \
            -e 's@\]\(\.\./\.\./((src|tests)/[^)#]+)(#[^)]*)?\)@](https://github.com/FixCraft-Inc/yume/blob/main/\1\3)@g' \
            -e 's@\]\(docs/protocol/([A-Z0-9_]+)\.md(#[^)]*)?\)@](/docs/protocol/\1/\2)@g' \
            -e 's@\]\(protocol/([A-Z0-9_]+)\.md(#[^)]*)?\)@](/docs/protocol/\1/\2)@g' \
            -e 's@\]\((YUME_2_0_[A-Z0-9_]+)\.md(#[^)]*)?\)@](/docs/protocol/\1/\2)@g' \
            -e 's@\]\(docs/([A-Z0-9_]+)\.md(#[^)]*)?\)@](/docs/\1/\2)@g' \
            -e 's@\]\(\.\./([A-Z0-9_]+)\.md(#[^)]*)?\)@](/docs/\1/\2)@g' \
            -e 's@\]\(([A-Z0-9_]+)\.md(#[^)]*)?\)@](/docs/\1/\2)@g' \
            "${source_path}"
    } > "${output_path}"
}

for source_path in "${repo_root}"/docs/*.md; do
    name="$(basename "${source_path}" .md)"
    render_doc "${source_path}" "${site_docs}/${name}.md" "/docs/${name}/"
done

render_doc \
    "${repo_root}/CONTRIBUTING.md" \
    "${site_docs}/CONTRIBUTING.md" \
    "/docs/CONTRIBUTING/"

for source_path in "${repo_root}"/docs/protocol/*.md; do
    name="$(basename "${source_path}" .md)"
    render_doc \
        "${source_path}" \
        "${site_docs}/protocol/${name}.md" \
        "/docs/protocol/${name}/"
done
