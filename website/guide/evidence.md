---
title: Evidence
description: How Securock records provenance, signature, vulnerability, malicious-package, capability, behavior, ownership, and trust-chain evidence states.
---

# Evidence

Securock stores evidence on each artifact in `securock.lock`. Reading
those states correctly is how you decide whether a package is trusted
under policy, merely unchecked, or actively failing a rule.

`trusted` still means “passed the active policy,” not “proven safe.”
See the [Trust model](/reference/trust-model) for the full matrix.

## Provenance, signature, and chain states

| State      | Meaning                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------- |
| `unknown`  | Lookup skipped or failed.                                                                   |
| `missing`  | Lookup succeeded and found nothing.                                                         |
| `present`  | Registry returned provenance, signatures, or a trust chain. Not cryptographically verified. |
| `verified` | Cryptographic verification succeeded and the subject digest matches the lockfile.           |

Provenance, signature, and chain use these states. npm evidence can
reach `verified` when registry keys / Sigstore roots are available and
the locked digest binds to the signed artifact.

How to read them:

- **`unknown`** — do not treat as clean. Offline mode and private
  registries leave many axes here.
- **`missing`** — Securock looked and found no attestation or signature.
- **`present`** — material exists but was not cryptographically verified
  (or verification did not bind the digest).
- **`verified`** — crypto check succeeded and matches the lockfile digest.

`require_provenance: true` accepts `present` or `verified`. To require
cryptographic verification, set `minimum: verified` under policy (or use
`--profile strict`). See [Policy](/guide/policy).

## Vulnerability and malicious states

| State     | Meaning                                                               |
| --------- | --------------------------------------------------------------------- |
| `unknown` | OSV was not queried (offline, private registry, or error).            |
| `checked` | OSV was queried. Vulns use `items`; malware uses `reports` (`MAL-*`). |

Malicious package reports are **not** vulnerabilities. A package with
no CVEs can still be malware. The default policy denies both.

Default policy treats `unknown` as unknown trust, **not** trusted.

## Capability, behavior, and ownership

Capability, behavior, and ownership use the same `unknown` / `checked`
states. Depth depends on the [ecosystem](/guide/ecosystems).

### npm family (npm / pnpm / Yarn / Bun / Deno npm)

Securock records:

- install scripts and native-code hints from the registry
- publisher and maintainers
- network, filesystem, environment, and shell indicators from published
  package sources
- finer-grained hosts, paths, commands, and env vars as `behavior`
- source → build → artifact fields from provenance attestations as
  `chain` (source, commit, ref, builder, workflow, predicate type)

Capability detection uses install-script and native-build metadata, then
a deterministic scan of published JS/TS sources. It is not a full
behavioral sandbox and may under-report obfuscated code.

Provenance verification for npm only accepts SLSA predicate types
(`https://slsa.dev/provenance/v0.1`, `v0.2`, and `v1`). Policy can
further limit accepted sources, builders, workflows, refs, and
predicate types via `allow_*` lists under `rules.provenance`; those
lists require a verified trust chain.

### PyPI (uv / Poetry / PDM)

Securock queries the Integrity API, reconstructs each PEP 740
attestation into a Sigstore bundle, and re-verifies it against the
public-good trust root (signer identity, artifact filename and digest,
DSSE signature, transparency log). A successful check records
provenance/signature `verified` with Trusted Publisher and certificate
identity on the chain; otherwise attestations remain `present`.

### Other ecosystems

Digest comes from the language lockfile. OSV runs when
`public-only` can prove a public origin. Provenance, signature,
capability, behavior, ownership, and chain usually stay `unknown`.

## Release health

Health describes the release itself rather than who published it. It
is recorded for npm-family packages and PyPI:

| Field        | Source                                                                   |
| ------------ | ------------------------------------------------------------------------ |
| `released`   | Publish day (`YYYY-MM-DD`). npm: the package document; PyPI: file upload |
| `deprecated` | The maintainers' deprecation message, or `yanked` and its reason on PyPI |
| `license`    | Declared license, preferably an SPDX expression                          |

`health` is omitted from the lockfile when the registry did not answer
(offline, private registry, unsupported ecosystem), so absence means
"not checked", never "healthy". For npm, `released` is also omitted for
packages whose full package document exceeds the 2 MiB response limit,
which is typical of packages with very long histories.

Health is informational: a change in `released` or `license` is not
trust drift. It affects trust only through the policy rule
[`health`](/guide/policy#health-and-typosquat-gates).

`securock audit` turns health into findings, and adds a name check that
needs no registry:

| Finding              | Severity | When                                                   |
| -------------------- | -------- | ------------------------------------------------------ |
| `deprecated-package` | medium   | The release is deprecated or yanked                    |
| `stale-release`      | low      | The release is more than two years old                 |
| `typosquat-suspect`  | medium   | npm or PyPI name within one edit of a popular package  |
| `recent-release`     | high     | Newer than `--min-release-age` (off unless you set it) |

`typosquat-suspect` compares each name against a built-in list of popular
packages (separator variants such as `lo-dash`, or one typo, swap, or
missing letter). Scoped npm names are skipped. It is a signal to look at,
not proof: a real package can have a name close to a popular one. Use
`securock accept` to record that you checked.

### Release cooldown

A freshly published malicious version is usually caught within days, so waiting a little
before adopting a release removes most of that risk. `securock audit --min-release-age 7d`
reports every npm and PyPI release published more recently than that as a high finding
(`recent-release`), so it fails `--fail-on high` by default. The age is a day count (`7d`)
or a duration (`72h`).

It is a report-time check, not a policy rule, on purpose: whether a release is "too new"
changes as time passes, and trust status in the lockfile must not. The registry gives only
the release day, so a release counts from the start of that day. A release whose date is
unknown (offline, a private registry, an npm package with a very long history) is not
flagged.

## Offline and private registries

`--offline` leaves remote evidence `unknown`. Private registries are
not queried in the default `public-only` network mode. Details:
[Privacy](/reference/privacy).

## Next steps

- [Policy](/guide/policy) — require floors and allowlists
- [Ecosystems](/guide/ecosystems) — where each evidence axis is collected
- [Trust model](/reference/trust-model) — trusted / untrusted / unknown
