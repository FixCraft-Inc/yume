const repo = "F1xGOD/yume";
const releaseApi = `https://api.github.com/repos/${repo}/releases/latest`;
let latestReleaseTag = "";
let latestReleaseData = null;

// Filenames must match what .github/workflows/release.yml `pack_one` /
// `pack_with_libs` produce. Most artifacts are bare binaries; only the
// Windows bundles are `.tar.xz` (so the runtime DLLs travel with the exe).
const assetMap = {
  "linux-amd64":  { bin: "yume-amd64-linux",       static: "yume-amd64-linux-static" },
  "linux-armv7":  { bin: "yume-armv7-linux" },
  "linux-armv8":  { bin: "yume-armv8-linux" },
  "openwrt-mips": { bin: "yume-mips-openwrt" },
  "busybox-amd64":{ bin: "yume-x86-busybox",       static: "yume-x86-busybox-static" },
  "busybox-armv7":{ bin: "yume-armv7-busybox",     static: "yume-armv7-busybox-static" },
  "busybox-armv8":{ bin: "yume-armv8-busybox",     static: "yume-armv8-busybox-static" },
  "mac-arm64":    { bin: "yume-armv8-mac" },
  "windows-amd64":{ bin: "yume-amd64-windows.tar.xz" }
};

function buildAssetUrl(name) {
  if (!name) return "";
  if (!latestReleaseTag) return "#";
  return `https://github.com/${repo}/releases/download/${latestReleaseTag}/${name}`;
}

function setDownloadLinks() {
  document.querySelectorAll("[data-download]").forEach(el => {
    const key = el.getAttribute("data-download");
    const variant = el.getAttribute("data-variant") || "bin";
    const entry = assetMap[key];
    if (!entry || !entry[variant]) {
      el.classList.add("disabled");
      el.setAttribute("href", "#");
      el.setAttribute("aria-disabled", "true");
      return;
    }
    el.setAttribute("href", buildAssetUrl(entry[variant]));
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener");
  });
}

function formatDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

async function loadLatestRelease() {
  try {
    const res = await fetch(releaseApi, { headers: { Accept: "application/vnd.github+json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    latestReleaseData = data;
    latestReleaseTag = data.tag_name || data.name || "";

    const versionEl = document.getElementById("release-version");
    const dateEl = document.getElementById("release-date");
    const assetsEl = document.getElementById("release-assets");
    const linkEl = document.getElementById("release-link");
    if (versionEl) versionEl.textContent = latestReleaseTag || "Not yet released";
    if (dateEl) dateEl.textContent = formatDate(data.published_at) || "Pre-release";
    if (assetsEl && Array.isArray(data.assets)) assetsEl.textContent = `${data.assets.length} assets`;
    if (linkEl && data.html_url) linkEl.setAttribute("href", data.html_url);
  } catch (err) {
    const versionEl = document.getElementById("release-version");
    const dateEl = document.getElementById("release-date");
    if (versionEl) versionEl.textContent = "Releases unavailable";
    if (dateEl) dateEl.textContent = "GitHub API offline";
  }
  setDownloadLinks();
}

function activateBrandMask() {
  const checkSvg = (url) => fetch(url).then(r => r.ok).catch(() => false);
  const base = document.documentElement.getAttribute("data-asset-base") || "assets/";
  checkSvg(base + "yume-white.svg").then(ok => {
    if (ok) document.body.classList.add("mask-ready");
  });
}

document.addEventListener("DOMContentLoaded", () => {
  activateBrandMask();
  loadLatestRelease();
});
