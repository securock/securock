# securock.dev

VitePress site for https://securock.dev.

```bash
cd website
npm install
npm run docs:dev
```

Build output is `.vitepress/dist`. Deploy that directory to Cloudflare Pages:

```bash
npm run docs:build
npx wrangler pages deploy .vitepress/dist --project-name securock-dev
```
