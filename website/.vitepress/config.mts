import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Securock',
  description: 'Supply-chain trust layer for software dependencies',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ['README.md'],
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/install' },
      { text: 'GitHub', link: 'https://github.com/securock/securock' },
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Install', link: '/guide/install' },
          { text: 'Usage', link: '/guide/usage' },
          { text: 'GitHub Action', link: '/guide/action' },
          { text: 'Evidence', link: '/guide/evidence' },
          { text: 'Privacy', link: 'https://github.com/securock/securock/blob/main/docs/privacy.md' },
        ],
      },
      {
        text: 'Specifications',
        items: [
          { text: 'Lockfile', link: 'https://github.com/securock/securock/blob/main/docs/specification.md' },
          { text: 'Trust model', link: 'https://github.com/securock/securock/blob/main/docs/trust-model.md' },
          { text: 'Threat model', link: 'https://github.com/securock/securock/blob/main/docs/threat-model.md' },
          { text: 'Security policy', link: 'https://github.com/securock/securock/blob/main/SECURITY.md' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/securock/securock' },
    ],
    footer: {
      message: 'Released under the Apache-2.0 License.',
      copyright: 'Securock',
    },
    search: {
      provider: 'local',
    },
    outline: 'deep',
    editLink: {
      pattern: 'https://github.com/securock/securock/edit/main/website/:path',
      text: 'Edit this page',
    },
  },
})
