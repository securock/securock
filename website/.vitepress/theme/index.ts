import DefaultTheme from 'vitepress/theme-without-fonts'
import type { Theme } from 'vitepress'
import Ledger from './Ledger.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('Ledger', Ledger)
  },
} satisfies Theme
