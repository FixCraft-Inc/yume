#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
site_docs="${repo_root}/website/docs"
mode="${1:-sync}"

if [[ "${mode}" != "sync" && "${mode}" != "--check" ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi

staging_root="$(mktemp -d)"
trap 'rm -rf "${staging_root}"' EXIT
generated_docs="${staging_root}/docs"
mkdir -p "${generated_docs}"

render_doc() {
    local source_path="$1"
    local output_path="$2"
    local permalink="$3"
    local source_relative
    local title

    source_relative="${source_path#"${repo_root}/"}"
    title="$(head -n 1 "${source_path}" | sed -E 's/^#[[:space:]]*//')"
    mkdir -p "$(dirname "${output_path}")"

    {
        printf '%s\n' '---'
        printf 'layout: doc\n'
        printf 'title: %s\n' "${title}"
        printf 'permalink: %s\n' "${permalink}"
        printf 'generated_from: %s\n' "${source_relative}"
        printf '%s\n\n' '---'
        sed -E \
            -e 's@\]\(\.\./\.\./((src|tests)/[^)#]+)(#[^)]*)?\)@](https://github.com/FixCraft-Inc/yume/blob/main/\1\3)@g' \
            -e 's@\]\(\.\./\.\./basefwx/([^)#]+)(#[^)]*)?\)@](https://github.com/F1xGOD/basefwx/blob/main/\1\2)@g' \
            -e 's@\]\(\.\./\.\./([^#)]+)(#[^)]*)?\)@](https://github.com/FixCraft-Inc/yume/blob/main/\1\2)@g' \
            -e 's@\]\(docs/protocol/([A-Z0-9_]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/protocol/\1/\2)@g' \
            -e 's@\]\(\.\./protocol/([A-Z0-9_]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/protocol/\1/\2)@g' \
            -e 's@\]\(protocol/([A-Z0-9_]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/protocol/\1/\2)@g' \
            -e 's@\]\(release/([A-Z0-9_.-]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/release/\1/\2)@g' \
            -e 's@\]\(agents/([A-Z0-9_.-]+)\.md(#[^)]*)?\)@](https://github.com/FixCraft-Inc/yume/blob/main/docs/agents/\1.md\2)@g' \
            -e 's@\]\(man/([A-Za-z0-9_.-]+)(#[^)]*)?\)@](https://github.com/FixCraft-Inc/yume/blob/main/docs/man/\1\2)@g' \
            -e 's@\]\((YUME_2_0_[A-Z0-9_]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/protocol/\1/\2)@g' \
            -e 's@\]\(docs/([A-Z0-9_]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/\1/\2)@g' \
            -e 's@\]\(\.\./([A-Z0-9_]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/\1/\2)@g' \
            -e 's@\]\(([A-Z0-9_]+)\.md(#[^)]*)?\)@]({{site.baseurl}}/docs/\1/\2)@g' \
            "${source_path}"
    } > "${output_path}"
}

for source_path in "${repo_root}"/docs/*.md; do
    name="$(basename "${source_path}" .md)"
    render_doc "${source_path}" "${generated_docs}/${name}.md" "/docs/${name}/"
done

render_doc \
    "${repo_root}/CONTRIBUTING.md" \
    "${generated_docs}/CONTRIBUTING.md" \
    "/docs/CONTRIBUTING/"

for source_path in "${repo_root}"/docs/protocol/*.md; do
    name="$(basename "${source_path}" .md)"
    render_doc \
        "${source_path}" \
        "${generated_docs}/protocol/${name}.md" \
        "/docs/protocol/${name}/"
done

for source_path in "${repo_root}"/docs/release/*.md; do
    name="$(basename "${source_path}" .md)"
    render_doc \
        "${source_path}" \
        "${generated_docs}/release/${name}.md" \
        "/docs/release/${name}/"
done

if [[ "${mode}" == "--check" ]]; then
    expected_list="${staging_root}/expected.list"
    actual_list="${staging_root}/actual.list"
    find "${generated_docs}" -type f -name '*.md' -printf '%P\n' | sort > "${expected_list}"
    find "${site_docs}" -type f -name '*.md' -printf '%P\n' | sort > "${actual_list}"
    if ! diff -u "${expected_list}" "${actual_list}"; then
        echo "website docs: generated file list is stale; run scripts/sync_website_docs.sh" >&2
        exit 1
    fi
    while IFS= read -r relative_path; do
        if ! diff -u "${generated_docs}/${relative_path}" "${site_docs}/${relative_path}"; then
            echo "website docs: ${relative_path} is stale; run scripts/sync_website_docs.sh" >&2
            exit 1
        fi
    done < "${expected_list}"
    echo "website docs: generated tree matches canonical Markdown"
    exit 0
fi

mkdir -p "${site_docs}"
rm -f "${site_docs}"/*.md
rm -rf "${site_docs}/agents" "${site_docs}/protocol" "${site_docs}/release"
cp -R "${generated_docs}/." "${site_docs}/"
