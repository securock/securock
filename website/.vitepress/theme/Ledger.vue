<template>
  <div class="ledger" aria-label="Trust drift example">
    <section>
      <h2>Locked</h2>
      <pre>react
  version       19.1.0
  provenance    present
  signature     present
  vulnerabilities none
  trust         trusted</pre>
    </section>
    <section>
      <h2>Current</h2>
      <pre>react
  version       19.1.0 → 19.2.0
  digest        changed
  provenance    present
  signature     present
  vulnerabilities none
  trust         trusted

Trust drift detected.</pre>
    </section>
  </div>
</template>

<style scoped>
.ledger {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  max-width: 920px;
  margin: 2.5rem auto 0;
  background: #f6f1ea;
  color: #16131a;
  box-shadow: 8px 8px 0 #16131a;
}

.dark .ledger {
  background: #221c28;
  color: #f3f0ea;
  box-shadow: 8px 8px 0 #c56a4a;
}

section {
  padding: 1rem 1.1rem 1.2rem;
}

section + section {
  border-left: 1px solid #16131a;
}

.dark section + section {
  border-left-color: #c56a4a;
}

h2 {
  margin: 0 0 0.75rem;
  font-family: 'IBM Plex Mono', ui-monospace, monospace;
  font-size: 0.78rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

pre {
  margin: 0;
  font-size: 0.86rem;
  white-space: pre-wrap;
  background: transparent;
  border: 0;
  padding: 0;
}

@media (max-width: 800px) {
  .ledger {
    grid-template-columns: 1fr;
  }

  section + section {
    border-left: 0;
    border-top: 1px solid #16131a;
  }
}
</style>
