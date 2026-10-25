import { defineConfig } from "vitepress";

const hostname = "https://securock.dev";

function canonicalUrl(relativePath: string): string {
  const path = relativePath
    .replace(/\\/g, "/")
    .replace(/(^|\/)index\.md$/, "$1")
    .replace(/\.md$/, "");
  if (!path || path === "/") {
    return `${hostname}/`;
  }
  return `${hostname}/${path.replace(/\/$/, "")}`;
}

export default defineConfig({
  title: "Securock",
  description:
    "A lockfile for trust, not just versions. Securock records dependency digests, provenance, signatures, and policy decisions in securock.lock, then fails CI when that trust state drifts.",
  lang: "en-US",
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ["README.md"],
  sitemap: {
    hostname,
  },
  head: [
    ["meta", { name: "theme-color", content: "#0f172a" }],
    ["meta", { name: "twitter:card", content: "summary" }],
    ["meta", { property: "og:site_name", content: "Securock" }],
  ],
  transformPageData(pageData) {
    const isHome = pageData.relativePath === "index.md";
    const canonical = canonicalUrl(pageData.relativePath);
    const title = pageData.title ? `${pageData.title} | Securock` : "Securock";
    const description =
      pageData.description ||
      pageData.frontmatter.description ||
      "Supply-chain trust layer for software dependencies";
    pageData.frontmatter.head ??= [];
    pageData.frontmatter.head.push(
      ["link", { rel: "canonical", href: canonical }],
      [
        "meta",
        {
          property: "og:type",
          content: isHome ? "website" : "article",
        },
      ],
      ["meta", { property: "og:title", content: title }],
      ["meta", { property: "og:description", content: description }],
      ["meta", { property: "og:url", content: canonical }],
      ["meta", { name: "twitter:title", content: title }],
      ["meta", { name: "twitter:description", content: description }],
      [
        "script",
        { type: "application/ld+json" },
        JSON.stringify(
          isHome
            ? {
                "@context": "https://schema.org",
                "@type": "SoftwareApplication",
                name: "Securock",
                applicationCategory: "DeveloperApplication",
                operatingSystem: "macOS, Linux",
                description,
                downloadUrl: `${hostname}/guide/install`,
                url: hostname,
                offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
              }
            : {
                "@context": "https://schema.org",
                "@type": "TechArticle",
                name: pageData.title,
                headline: `${pageData.title} | Securock`,
                description,
                url: canonical,
              },
        ),
      ],
    );
  },
  themeConfig: {
    nav: [
      { text: "Why", link: "/guide/why" },
      { text: "Guide", link: "/guide/quickstart" },
      { text: "Reference", link: "/reference/lockfile" },
      { text: "GitHub", link: "https://github.com/securock/securock" },
    ],
    sidebar: [
      {
        text: "Getting started",
        items: [
          { text: "Why Securock", link: "/guide/why" },
          { text: "Quick start", link: "/guide/quickstart" },
          { text: "Install", link: "/guide/install" },
        ],
      },
      {
        text: "Guide",
        items: [
          { text: "Usage", link: "/guide/usage" },
          { text: "Policy", link: "/guide/policy" },
          { text: "Evidence", link: "/guide/evidence" },
          { text: "Ecosystems", link: "/guide/ecosystems" },
        ],
      },
      {
        text: "Features",
        items: [
          { text: "Source code analysis", link: "/guide/sast" },
          { text: "Triage and exports", link: "/guide/reports" },
        ],
      },
      {
        text: "Integrations",
        items: [{ text: "GitHub Action", link: "/guide/action" }],
      },
      {
        text: "Reference",
        items: [
          { text: "Lockfile", link: "/reference/lockfile" },
          { text: "Privacy", link: "/reference/privacy" },
          { text: "Trust model", link: "/reference/trust-model" },
          { text: "Threat model", link: "/reference/threat-model" },
          { text: "SAST benchmarks", link: "/reference/sast-benchmarks" },
          { text: "FAQ", link: "/guide/faq" },
          {
            text: "Security policy",
            link: "https://github.com/securock/securock/blob/main/SECURITY.md",
          },
        ],
      },
    ],
    socialLinks: [
      { icon: "github", link: "https://github.com/securock/securock" },
    ],
    footer: {
      message:
        "Released under the Apache-2.0 License. Pre-1.0: all lockfile resolvers are stable.",
      copyright: "Securock",
    },
    search: {
      provider: "local",
    },
    outline: "deep",
    editLink: {
      pattern: "https://github.com/securock/securock/edit/main/website/:path",
      text: "Edit this page",
    },
  },
});
