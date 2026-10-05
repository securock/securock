# securock.dev

VitePress site for https://securock.dev.

```bash
cd website
npm install
npm run docs:dev
```

Build output is `.vitepress/dist`. Deploy with Wrangler to Cloudflare
Workers (static assets):

```bash
npm run docs:build
npx wrangler deploy
```

`wrangler.jsonc` binds the Worker to `securock.dev`. CI runs
`wrangler deploy` from `.github/workflows/website.yml`.
