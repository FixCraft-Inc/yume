const repo = "FixCraft-Inc/yume";
const releaseApi = `https://api.github.com/repos/${repo}/releases/latest`;
let latestReleaseData = null;

// The first stable CLI release workflow attaches exactly these two artifacts, plus a
// .sha256 sidecar for each, an aggregate SHA256SUMS.txt, and
// release-manifest.json. Detached .sig files appear only when the workflow has
// signing secrets. MD5 sidecars are no longer produced.
const assetMap = {
  "yume-linux-amd64": { bin: "yume-amd64-linux.tar.xz", component: "client" },
  "yumed-linux-amd64": { bin: "yumed-amd64-linux", component: "daemon" }
};

Object.values(assetMap).forEach((entry) => {
  entry.sha256 = `${entry.bin}.sha256`;
  entry.sig = `${entry.bin}.sig`;
});

const currentReleaseAssets = (data) => {
  const assets = Array.isArray(data?.assets) ? data.assets : [];
  const lookup = new Map(assets.map((asset) => [asset.name, asset]));
  const required = [
    ...Object.values(assetMap).flatMap((entry) => [entry.bin, entry.sha256]),
    "SHA256SUMS.txt",
    "release-manifest.json"
  ];
  if (!required.every((name) => lookup.has(name))) {
    throw new Error("latest release does not match the current artifact contract");
  }
  return { assets, lookup };
};

const setText = (id, value) => {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = value;
  }
};

const setAssetLinkElement = (el, url) => {
  if (!el) return;
  if (url) {
    el.href = url;
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener");
    el.classList.remove("disabled");
    el.removeAttribute("aria-disabled");
    el.removeAttribute("tabindex");
  } else {
    el.removeAttribute("href");
    el.removeAttribute("target");
    el.removeAttribute("rel");
    el.classList.add("disabled");
    el.setAttribute("aria-disabled", "true");
    el.setAttribute("tabindex", "-1");
  }
};

const initDisabledLinks = () => {
  document.querySelectorAll('a[aria-disabled="true"]').forEach((el) => {
    setAssetLinkElement(el, null);
  });
};

const setLinks = (selector, url) => {
  document.querySelectorAll(selector).forEach((el) => setAssetLinkElement(el, url));
};

const formatDate = (iso) => {
  if (!iso) return "Release date pending";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Release date pending";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
};

const fetchLatestRelease = async () => {
  if (latestReleaseData) {
    return latestReleaseData;
  }
  const response = await fetch(releaseApi, { headers: { Accept: "application/vnd.github+json" } });
  if (!response.ok) {
    throw new Error(`release fetch failed: ${response.status}`);
  }
  latestReleaseData = await response.json();
  return latestReleaseData;
};

const HASH_COLLAPSED_LEN = 32;

const showHash = (node, text) => {
  const value = String(text ?? "");
  const canTruncate = /^[a-f0-9]+$/i.test(value) && value.length > HASH_COLLAPSED_LEN;

  node.dataset.fullHash = value;
  node.classList.remove("expanded");
  node.textContent = canTruncate ? value.slice(0, HASH_COLLAPSED_LEN) : value;

  if (!canTruncate) {
    node.classList.remove("truncated");
    node.style.cursor = "default";
    node.onclick = null;
    node.onkeydown = null;
    node.removeAttribute("role");
    node.removeAttribute("tabindex");
    node.removeAttribute("aria-expanded");
    return;
  }
  node.classList.add("truncated");
  node.style.cursor = "pointer";
  node.setAttribute("role", "button");
  node.setAttribute("tabindex", "0");
  node.setAttribute("aria-expanded", "false");
  const toggle = function () {
    const expanded = this.classList.toggle("expanded");
    this.setAttribute("aria-expanded", String(expanded));
    this.textContent = expanded
      ? this.dataset.fullHash
      : this.dataset.fullHash.slice(0, HASH_COLLAPSED_LEN);
  };
  node.onclick = function (event) {
    event.preventDefault();
    toggle.call(this);
  };
  node.onkeydown = function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle.call(this);
    }
  };
};

const applyReleaseLinks = (assetLookup) => {
  Object.entries(assetMap).forEach(([key, values]) => {
    const binAsset = assetLookup.get(values.bin);
    const shaAsset = assetLookup.get(values.sha256);
    const sigAsset = assetLookup.get(values.sig);
    setLinks(`[data-download="${key}"]`, binAsset ? binAsset.browser_download_url : null);
    setLinks(`[data-asset="${key}.sha256"]`, shaAsset ? shaAsset.browser_download_url : null);
    setLinks(`[data-asset="${key}.sig"]`, sigAsset ? sigAsset.browser_download_url : null);
  });

  document.querySelectorAll("[data-asset-link]").forEach((el) => {
    const assetName = el.getAttribute("data-asset-link");
    const asset = assetName ? assetLookup.get(assetName) : null;
    setAssetLinkElement(el, asset ? asset.browser_download_url : null);
  });
};

const loadRelease = async () => {
  try {
    const data = await fetchLatestRelease();
    const { assets, lookup } = currentReleaseAssets(data);
    setText("release-version", data.name || data.tag_name || "Latest release");
    setText("release-date", formatDate(data.published_at));
    setText("release-assets", `${assets.length} assets`);
    setLinks("#release-link", data.html_url || "");
    applyReleaseLinks(lookup);
  } catch (_err) {
    // No published release, or GitHub is unreachable. The markup already
    // states the no-release default, so only overwrite it when it is stale.
    setText("release-assets", "");
    applyReleaseLinks(new Map());
  }
};

const parseSha256 = (body) => {
  const match = String(body || "").match(/\b[a-fA-F0-9]{64}\b/);
  return match ? match[0].toLowerCase() : "";
};

const loadHashFiles = async () => {
  const nodes = Array.from(document.querySelectorAll("[data-hash-file]"));
  if (!nodes.length) {
    return;
  }
  let assetLookup = new Map();
  try {
    const data = await fetchLatestRelease();
    assetLookup = currentReleaseAssets(data).lookup;
  } catch (_err) {
    nodes.forEach((node) => showHash(node, "No published release"));
    return;
  }
  await Promise.all(nodes.map(async (node) => {
    const asset = assetLookup.get(node.getAttribute("data-hash-file") || "");
    if (!asset) {
      showHash(node, "Not in this release");
      return;
    }
    try {
      const response = await fetch(asset.browser_download_url);
      if (!response.ok) {
        throw new Error(`sidecar fetch failed: ${response.status}`);
      }
      showHash(node, parseSha256(await response.text()) || "Unreadable sidecar");
    } catch (_err) {
      showHash(node, "Unavailable");
    }
  }));
};

const initNavScrollSpy = () => {
  const nav = document.querySelector(".section-nav");
  if (!nav) {
    return;
  }
  const links = Array.from(nav.querySelectorAll('a[href^="#"]'));
  const sections = links
    .map((link) => {
      const id = link.getAttribute("href")?.slice(1);
      const section = id ? document.getElementById(id) : null;
      return section ? { link, section } : null;
    })
    .filter(Boolean);

  if (!sections.length || !("IntersectionObserver" in window)) {
    return;
  }

  const setActive = (id) => {
    links.forEach((link) => {
      link.classList.toggle("active", (link.getAttribute("href") || "") === `#${id}`);
    });
  };

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (visible.length) {
        setActive(visible[0].target.id);
      }
    },
    { rootMargin: "-20% 0px -55% 0px", threshold: [0.1, 0.35, 0.6] }
  );

  sections.forEach(({ section }) => observer.observe(section));
};

const initDocToc = () => {
  const article = document.querySelector(".doc-article");
  const toc = document.getElementById("doc-toc-list");
  if (!article || !toc) return;

  const details = toc.closest(".doc-toc");
  if (window.matchMedia("(max-width: 920px)").matches) {
    details?.removeAttribute("open");
  }

  const headings = Array.from(article.querySelectorAll("h2, h3"));
  if (!headings.length) {
    details?.setAttribute("hidden", "");
    return;
  }

  const usedIds = new Set(Array.from(document.querySelectorAll("[id]"), (el) => el.id));
  headings.forEach((heading, index) => {
    if (!heading.id) {
      const base = heading.textContent
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "") || `section-${index + 1}`;
      let id = base;
      let suffix = 2;
      while (usedIds.has(id)) id = `${base}-${suffix++}`;
      heading.id = id;
      usedIds.add(id);
    }
    const link = document.createElement("a");
    link.href = `#${heading.id}`;
    link.dataset.level = heading.tagName.slice(1);
    link.textContent = heading.textContent;
    toc.appendChild(link);
  });
};

document.addEventListener("DOMContentLoaded", () => {
  initDisabledLinks();
  initNavScrollSpy();
  initDocToc();
  const run = async () => {
    if (document.getElementById("release-version") || document.querySelector("[data-download]")) {
      await loadRelease();
    }
    if (document.querySelector("[data-hash-file]")) {
      await loadHashFiles();
    }
  };
  run();
});
