const navEl = document.getElementById("nav");
const contentEl = document.getElementById("content");
const menuToggle = document.querySelector(".menu-toggle");
const sidebar = document.querySelector(".sidebar");
const overlay = document.querySelector(".overlay");

function toggleMenu(open) {
  const isOpen = open ?? !sidebar.classList.contains("open");
  sidebar.classList.toggle("open", isOpen);
  overlay?.classList.toggle("open", isOpen);
  menuToggle?.setAttribute("aria-expanded", isOpen);
  document.body.style.overflow = isOpen ? "hidden" : "";
}

menuToggle?.addEventListener("click", () => toggleMenu());
overlay?.addEventListener("click", () => toggleMenu(false));

// Close menu when nav link clicked (mobile)
navEl?.addEventListener("click", (e) => {
  if (e.target.closest("a")) toggleMenu(false);
});

const buildId = new URL(import.meta.url).searchParams.get("v") || "";

function withBuild(url) {
  if (!buildId) return url;
  const sep = url.includes("?") ? "&" : "?";
  return `${url}${sep}v=${encodeURIComponent(buildId)}`;
}

function escapeHtml(text) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function normalizeDocPath(docPath) {
  let p = String(docPath || "").trim();
  p = p.replaceAll("\\", "/");
  p = p.replace(/^\/+/, "");
  p = p.replace(/\.\.\//g, "");
  if (!p.endsWith(".md")) p += ".md";
  return p;
}

function getSelectedPath() {
  const hash = (location.hash || "").replace(/^#/, "");
  if (!hash) return null;
  return normalizeDocPath(hash);
}

function setSelectedPath(docPath) {
  location.hash = normalizeDocPath(docPath);
}

async function fetchJson(path) {
  const res = await fetch(withBuild(path), { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch ${path}: ${res.status}`);
  return res.json();
}

async function fetchText(path) {
  const res = await fetch(withBuild(path), { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch ${path}: ${res.status}`);
  return res.text();
}

function renderNav(pages, activePath) {
  if (!pages.length) {
    navEl.innerHTML = "";
    return;
  }

  navEl.innerHTML = pages
    .map((p) => {
      const path = normalizeDocPath(p.path);
      const title = escapeHtml(p.title || path);
      const current = activePath === path ? ` aria-current="page"` : "";
      return `<a href="#${encodeURIComponent(path)}"${current}>${title}</a>`;
    })
    .join("");
}

function installContentLinkHandler() {
  contentEl.addEventListener("click", (e) => {
    const a = e.target?.closest?.("a");
    if (!a) return;

    const href = a.getAttribute("href") || "";
    if (
      href.startsWith("http://") ||
      href.startsWith("https://") ||
      href.startsWith("mailto:") ||
      href.startsWith("#")
    ) {
      return;
    }

    // Route relative markdown links through the SPA.
    if (href.endsWith(".md")) {
      e.preventDefault();
      setSelectedPath(href);
      return;
    }
  });
}

async function main() {
  // SPA fallback: convert pathname to hash route so deep links work
  // e.g. /roadmap -> #roadmap.md, /devlog/001 -> #devlog/001.md
  if (location.pathname !== "/" && !location.hash) {
    const path = location.pathname.replace(/^\/+/, "");
    if (path) {
      location.replace("#" + normalizeDocPath(path));
      return;
    }
  }

  if (!globalThis.marked) {
    contentEl.innerHTML = `<p class="empty">Markdown renderer failed to load.</p>`;
    return;
  }

  installContentLinkHandler();

  let manifest;
  try {
    manifest = await fetchJson("./manifest.json");
  } catch (e) {
    contentEl.innerHTML = `<p class="empty">Missing <code>manifest.json</code>. Deploy the site via CI.</p>`;
    navEl.innerHTML = "";
    console.error(e);
    return;
  }

  const pages = Array.isArray(manifest.pages) ? manifest.pages : [];
  const defaultPath = pages[0]?.path ? normalizeDocPath(pages[0].path) : null;

  async function render() {
    const activePath = getSelectedPath() || defaultPath;
    renderNav(pages, activePath);

    if (!activePath) {
      contentEl.innerHTML = `<p class="empty">No docs yet. Add markdown files under <code>zat/docs/</code> and push to <code>main</code>.</p>`;
      return;
    }

    try {
      const md = await fetchText(`./docs/${activePath}`);
      const html = globalThis.marked.parse(md);
      contentEl.innerHTML = html;

      // Update current marker after navigation re-render.
      for (const a of navEl.querySelectorAll("a")) {
        const href = decodeURIComponent((a.getAttribute("href") || "").slice(1));
        a.toggleAttribute("aria-current", normalizeDocPath(href) === activePath);
      }
    } catch (e) {
      contentEl.innerHTML = `<p class="empty">Failed to load <code>${escapeHtml(
        activePath,
      )}</code>.</p>`;
      console.error(e);
    }
  }

  window.addEventListener("hashchange", () => render());

  if (!getSelectedPath() && defaultPath) setSelectedPath(defaultPath);
  await render();
}

main();
