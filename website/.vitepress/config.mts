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
  description: "Supply-chain trust layer for software dependencies",
  lang: "en-US",
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ["README.md"],
  sitemap: {
    hostname,
  },
  head: [
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:site_name", content: "Securock" }],
    ["meta", { name: "twitter:card", content: "summary" }],
  ],
  transformPageData(pageData) {
    const canonical = canonicalUrl(pageData.relativePath);
    const title = pageData.title ? `${pageData.title} | Securock` : "Securock";
    const description =
      pageData.description ||
      pageData.frontmatter.description ||
      "Supply-chain trust layer for software dependencies";

    pageData.frontmatter.head ??= [];
    pageData.frontmatter.head.push(
      ["link", { rel: "canonical", href: canonical }],
      ["meta", { property: "og:title", content: title }],
      ["meta", { property: "og:description", content: description }],
      ["meta", { property: "og:url", content: canonical }],
      ["meta", { name: "twitter:title", content: title }],
      ["meta", { name: "twitter:description", content: description }],
    );
  },
  themeConfig: {
    nav: [
      { text: "Guide", link: "/guide/quickstart" },
      { text: "GitHub", link: "https://github.com/securock/securock" },
    ],
    sidebar: [
      {
        text: "Guide",
        items: [
          { text: "Quick start", link: "/guide/quickstart" },
          { text: "Install", link: "/guide/install" },
          { text: "Usage", link: "/guide/usage" },
          { text: "Policy", link: "/guide/policy" },
          { text: "Ecosystems", link: "/guide/ecosystems" },
          { text: "Evidence", link: "/guide/evidence" },
          { text: "GitHub Action", link: "/guide/action" },
        ],
      },
      {
        text: "Reference",
        items: [
          { text: "Lockfile", link: "/reference/lockfile" },
          { text: "Privacy", link: "/reference/privacy" },
          { text: "Trust model", link: "/reference/trust-model" },
          { text: "Threat model", link: "/reference/threat-model" },
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
      message: "Released under the Apache-2.0 License.",
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
