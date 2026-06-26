const repo = "FixCraft-Inc/yume";
const releaseApi = `https://api.github.com/repos/${repo}/releases/latest`;
let latestReleaseTag = "";
let latestReleaseData = null;

const STATUS_OK_ICON = `
  <svg class="status-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" aria-hidden="true">
    <path d="M382-240 154-468l57-57 171 171 367-367 57 57-424 424Z" />
  </svg>
`;
const STATUS_WARN_ICON = `
  <svg class="status-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" aria-hidden="true">
    <path d="m40-120 440-760 440 760H40Zm138-80h604L480-720 178-200Zm302-40q17 0 28.5-11.5T520-280q0-17-11.5-28.5T480-320q-17 0-28.5 11.5T440-280q0 17 11.5 28.5T480-240Zm-40-120h80v-200h-80v200Zm40-100Z" />
  </svg>
`;
const STATUS_BAD_ICON = `
  <svg class="status-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" aria-hidden="true">
    <path d="M330-120 120-330v-300l210-210h300l210 210v300L630-120H330Zm36-190 114-114 114 114 56-56-114-114 114-114-56-56-114 114-114-114-56 56 114 114-114 114 56 56Zm-2 110h232l164-164v-232L596-760H364L200-596v232l164 164Zm116-280Z" />
  </svg>
`;

const assetMap = {
  "yume-linux-amd64": { bin: "yume-amd64-linux", group: "linux", component: "client" },
  "yumed-linux-amd64": { bin: "yumed-amd64-linux", group: "linux", component: "daemon" },
  "yume-linux-amd64-static": { bin: "yume-amd64-linux-static", group: "linux", component: "client" },
  "yumed-linux-amd64-static": { bin: "yumed-amd64-linux-static", group: "linux", component: "daemon" },
  "yume-gui-linux-amd64": { bin: "yume-gui-amd64-linux", group: "linux", component: "gui" },
  "yume-linux-armv7": { bin: "yume-armv7-linux", group: "linux", component: "client" },
  "yumed-linux-armv7": { bin: "yumed-armv7-linux", group: "linux", component: "daemon" },
  "yume-linux-armv8": { bin: "yume-armv8-linux", group: "linux", component: "client" },
  "yumed-linux-armv8": { bin: "yumed-armv8-linux", group: "linux", component: "daemon" },
  "yume-openwrt-mips": { bin: "yume-mips-openwrt", group: "embedded", component: "client" },
  "yumed-openwrt-mips": { bin: "yumed-mips-openwrt", group: "embedded", component: "daemon" },
  // BusyBox/embedded builds only ship as truly-static binaries (verified
  // by the release workflow's static-link assertion). The dynamic
  // "busybox" variants were dropped because they're misleading — a
  // glibc-dynamic binary can't run on a real busybox/musl target.
  "yume-busybox-amd64-static": { bin: "yume-x86-busybox-static", group: "embedded", component: "client" },
  "yumed-busybox-amd64-static": { bin: "yumed-x86-busybox-static", group: "embedded", component: "daemon" },
  "yume-busybox-armv7-static": { bin: "yume-armv7-busybox-static", group: "embedded", component: "client" },
  "yumed-busybox-armv7-static": { bin: "yumed-armv7-busybox-static", group: "embedded", component: "daemon" },
  "yume-busybox-armv8-static": { bin: "yume-armv8-busybox-static", group: "embedded", component: "client" },
  "yumed-busybox-armv8-static": { bin: "yumed-armv8-busybox-static", group: "embedded", component: "daemon" },
  "yume-macos-arm64": { bin: "yume-armv8-mac", group: "macos", component: "client" },
  "yumed-macos-arm64": { bin: "yumed-armv8-mac", group: "macos", component: "daemon" },
  "yume-gui-macos-arm64": { bin: "yume-gui-armv8-mac", group: "macos", component: "gui" },
  "yume-windows-amd64": { bin: "yume-amd64-windows.tar.xz", group: "windows", component: "client" },
  "yumed-windows-amd64": { bin: "yumed-amd64-windows.tar.xz", group: "windows", component: "daemon" },
  "yume-gui-windows-amd64": { bin: "yume-gui-amd64-windows.exe", group: "windows", component: "gui" }
};

Object.values(assetMap).forEach((entry) => {
  entry.sha256 = `${entry.bin}.sha256`;
  entry.md5 = `${entry.bin}.md5`;
  entry.sig = `${entry.bin}.sig`;
});

const setText = (id, value) => {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = value;
  }
};

const getAssetBase = () => document.documentElement.dataset.assetBase || "assets/";

const getResultsLocalBase = () => {
  const base = document.documentElement.dataset.resultsBase;
  return new URL(base || "results/", window.location.href).toString();
};

const getResultsBases = () => {
  const devBase = `https://raw.githubusercontent.com/${repo}/DEV/website/results`;
  return {
    primary: devBase,
    fallback: devBase
  };
};

const initBrandMask = () => {
  if (!window.CSS || !CSS.supports) {
    return;
  }
  const maskUrl = new URL(`${getAssetBase()}yume-white.svg`, window.location.href).toString();
  const supportsMask =
    CSS.supports("mask-image", `url("${maskUrl}")`) ||
    CSS.supports("-webkit-mask-image", `url("${maskUrl}")`);
  if (!supportsMask) {
    return;
  }
  const img = new Image();
  img.onload = () => document.documentElement.classList.add("mask-ready");
  img.src = maskUrl;
};

const setAssetLinkElement = (el, url) => {
  if (!el) return;
  if (url) {
    el.href = url;
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener");
    el.classList.remove("disabled");
    el.removeAttribute("aria-disabled");
  } else {
    el.href = "#";
    el.classList.add("disabled");
    el.setAttribute("aria-disabled", "true");
  }
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
  latestReleaseTag = latestReleaseData.tag_name || latestReleaseData.name || "";
  return latestReleaseData;
};

const HASH_COLLAPSED_LEN = 32;

const setHashText = (selector, value) => {
  const el = document.querySelector(`[data-hash="${selector}"]`);
  if (!el) return;
  const text = typeof value === "string" ? value : String(value ?? "");
  const isHashLike = /^[a-f0-9]+$/i.test(text);
  const canTruncate = isHashLike && text.length > HASH_COLLAPSED_LEN;

  el.dataset.fullHash = text;
  el.classList.remove("expanded");
  el.textContent = canTruncate ? text.slice(0, HASH_COLLAPSED_LEN) : text;

  if (canTruncate) {
    el.classList.add("truncated");
    el.style.cursor = "pointer";
    el.onclick = function (event) {
      event.preventDefault();
      const expanded = this.classList.toggle("expanded");
      this.textContent = expanded
        ? this.dataset.fullHash || ""
        : (this.dataset.fullHash || "").slice(0, HASH_COLLAPSED_LEN);
    };
  } else {
    el.classList.remove("truncated");
    el.style.cursor = "default";
    el.onclick = null;
  }
};

const applyReleaseLinks = (assetLookup) => {
  Object.entries(assetMap).forEach(([key, values]) => {
    const binAsset = assetLookup.get(values.bin);
    const shaAsset = assetLookup.get(values.sha256);
    const md5Asset = assetLookup.get(values.md5);
    const sigAsset = assetLookup.get(values.sig);
    setLinks(`[data-download="${key}"]`, binAsset ? binAsset.browser_download_url : null);
    setLinks(`[data-asset="${key}.sha256"]`, shaAsset ? shaAsset.browser_download_url : null);
    setLinks(`[data-asset="${key}.md5"]`, md5Asset ? md5Asset.browser_download_url : null);
    setLinks(`[data-asset="${key}.sig"]`, sigAsset ? sigAsset.browser_download_url : null);
    setHashText(`${key}.sha256`, "Loading...");
    setHashText(`${key}.md5`, "Loading...");
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
    const assets = Array.isArray(data.assets) ? data.assets : [];
    const assetLookup = new Map(assets.map((asset) => [asset.name, asset]));
    setText("release-version", data.name || data.tag_name || "Latest release");
    setText("release-date", formatDate(data.published_at));
    setText("release-assets", `${assets.length} assets`);
    setLinks("#release-link", data.html_url || "");
    setLinks("#download-cta", data.html_url || "");
    applyReleaseLinks(assetLookup);
  } catch (_err) {
    setText("release-version", "Release data unavailable");
    setText("release-date", "Check GitHub for details");
    setText("release-assets", "-");
    applyReleaseLinks(new Map());
  }
};

const parseHashFile = (assetName, body) => {
  const expectedLength = assetName.endsWith(".md5") ? 32 : 64;
  const matcher = new RegExp(`\\b[a-fA-F0-9]{${expectedLength}}\\b`);
  const match = String(body || "").match(matcher);
  if (match) {
    return match[0].toLowerCase();
  }
  return String(body || "").trim().split(/\s+/)[0] || "Unavailable";
};

const fetchFirstText = async (urls) => {
  for (const url of urls.filter(Boolean)) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return response.text();
      }
    } catch (_err) {
      // Try the next source.
    }
  }
  throw new Error("all fetch candidates failed");
};

const loadHashFiles = async () => {
  const nodes = Array.from(document.querySelectorAll("[data-hash-file]"));
  if (!nodes.length) {
    return;
  }
  try {
    const data = await fetchLatestRelease();
    const assets = Array.isArray(data.assets) ? data.assets : [];
    const assetLookup = new Map(assets.map((asset) => [asset.name, asset]));
    const localBase = getResultsLocalBase();
    await Promise.all(nodes.map(async (node) => {
      const assetName = node.getAttribute("data-hash-file");
      if (!assetName) {
        node.textContent = "Unavailable";
        return;
      }
      const asset = assetLookup.get(assetName);
      const urls = [
        asset ? asset.browser_download_url : "",
        `${localBase}${assetName}`
      ];
      try {
        node.textContent = parseHashFile(assetName, await fetchFirstText(urls));
      } catch (_err) {
        node.textContent = asset ? "Unavailable" : "Missing release asset";
      }
    }));
  } catch (_err) {
    nodes.forEach((node) => {
      node.textContent = "Unavailable";
    });
  }
};

const statusCell = (statusClass, label, icon) => `
  <span class="status-mark ${statusClass}" aria-label="${label}" title="${label}">${icon}</span>
`;

const loadVirusTotal = async () => {
  const summary = document.getElementById("vt-summary");
  const tableBody = document.querySelector("#vt-table tbody");
  if (!summary || !tableBody) {
    return;
  }
  try {
    const resultsBases = getResultsBases();
    const localBase = getResultsLocalBase();
    const releaseAssets = Array.isArray(latestReleaseData?.assets) ? latestReleaseData.assets : [];
    const releaseJsonAsset = releaseAssets.find((asset) =>
      ["virustotal-results.json", "virustotal-latest.json"].includes(asset.name)
    );
    const releaseTextAsset = releaseAssets.find((asset) =>
      ["virustotal-results.txt", "virustotal-latest.txt", "results.txt"].includes(asset.name)
    );
    const candidates = [
      releaseJsonAsset ? releaseJsonAsset.browser_download_url : "",
      `${resultsBases.primary}/virustotal-latest.json`,
      latestReleaseTag ? `${resultsBases.primary}/virustotal-${latestReleaseTag}.json` : "",
      `${resultsBases.fallback}/virustotal-latest.json`,
      latestReleaseTag ? `${resultsBases.fallback}/virustotal-${latestReleaseTag}.json` : "",
      `${localBase}virustotal-latest.json`
    ].filter(Boolean);

    let resultsUrl = "";
    let response = null;
    for (const candidate of candidates) {
      try {
        const attempt = await fetch(candidate);
        if (attempt.ok) {
          resultsUrl = candidate;
          response = attempt;
          break;
        }
      } catch (_err) {
        // Try the next source.
      }
    }
    if (!response) {
      throw new Error("vt results not found");
    }

    setLinks("#vt-results-json", resultsUrl);
    setLinks("#vt-results-text", releaseTextAsset ? releaseTextAsset.browser_download_url : resultsUrl.replace(/\.json$/, ".txt"));
    const data = await response.json();
    const files = Array.isArray(data.files) ? data.files : [];
    const generatedAt = data.generated_at ? new Date(data.generated_at).toLocaleString() : "unknown time";
    summary.textContent = `Report generated ${generatedAt} for ${data.release_tag || "latest"}`;
    summary.className = "status-pill ok";

    tableBody.innerHTML = "";
    files.forEach((file) => {
      const rawStats = file.stats || {};
      const stats = file.effective_stats || rawStats;
      const malicious = Number(stats.malicious ?? 0);
      const suspicious = Number(stats.suspicious ?? 0);
      const undetected = Number(stats.undetected ?? 0);
      const validSha256 = typeof file.sha256 === "string" && /^[a-f0-9]{64}$/i.test(file.sha256);
      const link = validSha256 ? `https://www.virustotal.com/gui/file/${file.sha256}` : "";
      let cls = "warn";
      let label = "VirusTotal caution";
      let icon = STATUS_WARN_ICON;
      if (malicious >= 4 || suspicious >= 7) {
        cls = "bad";
        label = "VirusTotal high risk";
        icon = STATUS_BAD_ICON;
      } else if (malicious === 0 && suspicious === 0 && undetected > 0 && validSha256) {
        cls = "ok";
        label = "VirusTotal pass";
        icon = STATUS_OK_ICON;
      }
      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="mono">
          <div class="vt-file-cell">
            ${statusCell(cls, label, icon)}
            ${file.name || ""}
          </div>
        </td>
        <td>${malicious}</td>
        <td>${suspicious}</td>
        <td>${undetected}</td>
        <td>${link ? `<a class="vt-btn" href="${link}" target="_blank" rel="noopener">View report</a>` : "n/a"}</td>
      `;
      tableBody.appendChild(row);
    });
    if (!files.length) {
      tableBody.innerHTML = "<tr><td colspan=\"5\" class=\"mono\">No scanned files in this report.</td></tr>";
    }
  } catch (_err) {
    summary.textContent = "VirusTotal results not available yet.";
    summary.className = "status-pill warn";
    tableBody.innerHTML = "<tr><td colspan=\"5\" class=\"mono\">No results found.</td></tr>";
  }
};

const initNavScrollSpy = () => {
  const nav = document.querySelector(".site-header nav");
  if (!nav) {
    return;
  }
  const links = Array.from(nav.querySelectorAll('a[href^="#"]'));
  if (!links.length) {
    return;
  }
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
      const href = link.getAttribute("href") || "";
      link.classList.toggle("active", href === `#${id}`);
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
  setActive(sections[0].section.id);
};

document.addEventListener("DOMContentLoaded", () => {
  initBrandMask();
  initNavScrollSpy();
  const run = async () => {
    if (document.getElementById("release-version") || document.querySelector("[data-download]")) {
      await loadRelease();
    }
    if (document.querySelector("[data-hash-file]")) {
      await loadHashFiles();
    }
    if (document.getElementById("vt-table")) {
      await loadVirusTotal();
    }
  };
  run();
});
