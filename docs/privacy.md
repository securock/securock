# Privacy

Securock may send public dependency names and versions to third parties
when it looks up vulnerabilities and package evidence. For npm capability
and behavior scanning it may also download public package tarballs from
the registry. For PyPI it may query the Integrity API for public file
provenance.

## Live application checks (DAST)

`securock dast URL...` and `securock security --target URL` contact only the
application URLs you explicitly supply and redirects within the same scheme,
host, and effective port. These checks require `--network allow-all` or the
same mode in the selected policy. `--offline` and `--network offline` always
refuse DAST before contacting a target; `public-only` also refuses it, even if
the application happens to share a public registry host. The registry allowlist
is a filter for public-only dependency evidence, not an application target
allowlist. Allow-all bypasses that registry filter for dependency evidence.

DAST sends GET requests with a `securock-dast` user agent. It follows at most
five redirects per target, uses a total timeout of 15 seconds per target by
default, and keeps normal TLS certificate verification and environment proxy
settings. It does not crawl links, submit forms, inject payloads, authenticate,
replay response cookies, or cache responses. Reports retain the target URL and
cookie names, but not response bodies, cookie values, or raw response headers.
Targets and redirects with URL credentials, query parameters, or fragments
are refused. Target paths appear in reports, so do not put credentials in paths.

Use a staging or other application you are authorized to inspect. Even a GET
can trigger application-specific behavior. For `security --target`, allow-all
also applies to dependency evidence as described below; use standalone `dast`
when you only want live application checks.

## AWS cloud posture checks (CSPM)

`securock cspm inventory.json --offline` and `security --cloud-inventory` read
local AWS Config JSON exports without contacting a cloud service. Resource IDs,
account IDs, regions, evaluated setting names, and finding summaries appear in
reports. Configuration values, policy documents, credentials, and raw inventories
are not included in reports. Treat the inventory itself as sensitive input.

`--aws-region REGION` explicitly enables read-only collection through an installed
AWS CLI v2 using `configservice select-resource-config`. It requires
`--network allow-all` or that mode in the selected policy. Offline and public-only
modes refuse collection before starting the CLI. The registry allowlist is not
an AWS endpoint allowlist. The CLI contacts the region's AWS Config endpoint
(normally `config.REGION.amazonaws.com`, or the partition's equivalent), and its
configured credential providers may contact STS, IAM Identity Center/SSO,
instance metadata, or other configured credential endpoints. Environment proxy,
AWS endpoint, credential, and profile settings remain in effect.

Securock passes a fixed SELECT query for supported resource types, the region,
and optional profile as separate process arguments; it does not invoke a shell
or modify resources. Collection has a 60-second timeout and a 16 MiB output
limit, uses AWS CLI auto-pagination, and does not save the raw result to disk.
CLI stderr is omitted from reports because it can contain sensitive details.
Credentials are managed through the existing AWS CLI configuration, not flags
or chat. Provider configuration and network policy must permit the intended
endpoints. Live AWS Config data is recorded state, not a real-time API inspection
of every resource. Account coverage and freshness are explicitly not established.
For `security --aws-region`, allow-all also applies to dependency evidence;
standalone `cspm` performs only the selected cloud posture checks.

## Default: public-only

The default network mode is `public-only`. Securock only queries:

- OSV (`https://api.osv.dev`): the batch query by package name and version, and the advisory
  record (`/v1/vulns/<id>`) of each advisory that matched, for its severity and fixed version
- the npm registry (`https://registry.npmjs.org`) and Yarn's default
  (`https://registry.yarnpkg.com`)
- deps.dev (`https://api.deps.dev/v3/systems/npm/...`), only to date an npm release whose
  package document is too large to read (react, typescript, webpack), and only for packages
  from the public npm registry
- the PyPI Integrity API (`https://pypi.org/integrity/...`) and JSON API
  (`https://pypi.org/pypi/<project>/<version>/json`, for license, release date and yanked
  status) for public PyPI artifacts with a filename in the language lockfile

and only for artifacts whose lockfile registry is a known public registry:

| Ecosystem | Allowed registries |
| --- | --- |
| npm | `https://registry.npmjs.org`, `https://registry.yarnpkg.com` |
| cargo | crates.io index URLs |
| go | `https://proxy.golang.org` when the effective `GOPROXY` is that single public proxy (OS, then `go env -w` / `GOENV`, then Go's default). Multiple proxy URLs (`,` or `|`) are unknown. `GONOPROXY` overrides `GOPRIVATE` for proxy use; `GOPRIVATE` still keeps names off OSV. |
| pypi | `https://pypi.org` |
| packagist | `https://repo.packagist.org` |
| rubygems | `https://rubygems.org` |
| nuget | `https://api.nuget.org` |
| pub | `https://pub.dev` |
| hex | `https://repo.hex.pm` |
| hackage | `https://hackage.haskell.org` (only when `cabal.project.freeze` lists `hackage.haskell.org` as its sole active repository and `cabal.project` declares no `repository`) |
| cran | `https://cloud.r-project.org`, `https://cran.r-project.org` (only for packages from the `CRAN` repository; Bioconductor, Posit Package Manager and other mirrors are unknown) |
| jsr | `https://jsr.io` (names are not sent to OSV yet) |

Private registries, missing `resolved` URLs, custom or ambiguous
`GOPROXY` lists, and `GOPRIVATE` / `GONOPROXY` modules are recorded in
`securock.lock` but are **not** sent off-machine. Their vulnerability
state is `unknown`, not `trusted`. Effective Go values include
`go env -w` (the user `GOENV` file), not only OS environment variables.
`GONOPROXY=none` can send `GOPRIVATE` modules through a proxy, but
those names are still not sent to OSV. For Go `replace`, privacy and
OSV use the replacement module path, not the original require path.
Swift package URLs are recorded the same way: `public-only` does not
treat Git hosts as a public registry.

pnpm often omits tarball URLs. Securock does **not** assume
`registry.npmjs.org` in that case. It only treats a package as public when
a tarball origin or an explicit registry setting (environment, project
`.npmrc` / `.yarnrc.yml`, parent `.yarnrc.yml`, or user `~/.npmrc` /
`~/.yarnrc.yml`) proves a public origin. Yarn Berry projects without a
registry setting use Yarn's documented default,
`https://registry.yarnpkg.com`, which is treated as public npm. The same
fail-closed rule applies to NuGet (`NuGet.Config` package sources, merged
like NuGet from machine and user configs through every parent directory
down to the project), PDM (lockfile file URLs, plus `[[tool.pdm.source]]`
and PDM config indexes; the default PyPI index is treated as public), Mix
(`mix.lock` repository identity), and Gradle (`gradle.lockfile` has no
repository URL). Mixed public and private sources are treated as unknown.

## Exploitation data (opt-in)

`securock audit --prioritize` is the only command that contacts these hosts, and only when you
pass the flag. It sends the CVE identifiers of advisories that OSV matched, never package names or
versions:

- OSV (`https://api.osv.dev/v1/vulns/<id>`), to read the CVE aliases of each matched advisory
- CISA (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`):
  the whole Known Exploited Vulnerabilities catalog, downloaded without sending anything
- FIRST (`https://api.first.org/data/v1/epss?cve=...`): the EPSS score of those CVEs

It follows the network mode: `--offline` skips it and `audit` reports an `info` finding saying so,
and in `public-only` mode only advisories of artifacts from a known public registry exist to look
up. Nothing is written to `securock.lock`.

## OpenSSF Scorecard (opt-in)

`securock audit --min-scorecard <score>` and `securock audit --scorecard` are the only commands that
contact these endpoints, and only when you pass one of the flags. For each package that the network mode allows to leave the machine, it sends
the ecosystem, package name and version to deps.dev:

- `https://api.deps.dev/v3/systems/<system>/packages/<name>/versions/<version>`, to find the source
  repository the package points at
- `https://api.deps.dev/v3/projects/<repository>`, for that repository's OpenSSF Scorecard

Only npm, PyPI, Cargo, Go, NuGet and RubyGems packages are looked up. `--offline` skips it, and in
`public-only` mode a package from a private registry, a `GOPRIVATE` module or a Git source is not
sent: it counts toward an `info` finding, `scorecard-unchecked`, that says how many packages have no
score. Nothing is written to `securock.lock`.

## Local cache

Responses from OSV, the registries, the exploitation feeds and deps.dev are kept for one hour in your user cache
directory (`securock/`), readable only by you, so repeated runs do not ask again. They
hold the same public data that was already sent off-machine, never credentials: a
request that carries `Authorization`, `Proxy-Authorization`, or `Cookie` is not
cached. `--no-cache` skips the cache for one run, `--cache-ttl` changes its lifetime,
and `securock cache clear` deletes it.

## Modes

```sh
securock scan --offline
securock scan --network public-only
securock scan --network allow-all
```

`--offline` skips all remote lookups. `allow-all` sends every dependency
name and version to OSV and, for supported collectors, registry evidence
endpoints (npm attestations/signatures and PyPI Integrity API). Use it
only when that disclosure is acceptable.

Policy files can set the same mode:

```yaml
version: 1
network:
  mode: public-only
  registries:
    npm:
      - https://registry.npmjs.org
rules:
  require_no_vulnerabilities: true
```

Unknown policy fields are rejected.

## Container scanners

The explicit `container` command invokes installed Trivy. Online image scans
require allow-all and may contact the selected registry and Trivy's configured
vulnerability database repositories (normally ghcr.io). Local offline archives
disable database updates and version checks and require preinstalled databases.
Trivy manages registry authentication; Securock does not accept credential flags.
Raw scanner stderr is not copied into reports.

## Authenticated and browser DAST

Explicit `dast --bearer-env NAME` forwards that environment variable as a bearer
token to the chosen origin only. It is not written to reports or command arguments.
`--browser` executes application JavaScript in installed Playwright Chromium;
request interception blocks other origins, mutating methods, WebSockets and
requests beyond 100. Service workers are blocked. Browser errors are reported
as incomplete scans; raw browser diagnostics are not included.

## Azure and GCP collection

Explicit Azure subscription and GCP project flags require allow-all. Installed
`az graph query` contacts Azure Resource Graph (management.azure.com) and its
configured credential endpoints. `gcloud asset list --content-type resource`
contacts cloudasset.googleapis.com and configured Google authentication endpoints.
Their existing credential providers and proxy settings apply. Resource exports
are parsed in memory; raw properties and provider stderr are not printed.

## Monitoring notifications

Only explicit `watch --webhook-env` enables notification delivery, and requires
allow-all. New findings at the configured threshold, including resource/target
identities and remediation, are POSTed as JSON to that environment variable's
HTTPS URL. Redirects are not followed. URLs are not copied into reports. Local
monitoring state contains prior finding reports and is created with private
permissions; protect it as project security data.

## Enterprise management and private runners

Management clients contact only the explicitly configured control-plane origin
using bearer tokens, without redirects. `runner` requires `--network allow-all`;
offline refuses it. Offline scans execute locally, but their findings are uploaded
to the configured service. No source checkout is uploaded. The control service
stores tenant memberships, findings, jobs and audit records in encrypted state.
Operate the service in an approved region, separately manage encryption/signing
keys, and review report snippets, retention, backups and support exports.

## Configured workflow connectors

With explicit `--connectors` and `--network allow-all`, the service sends queued
titles, descriptions, commit IDs and branch names to operator-configured HTTPS
GitHub/GitLab/Jira/ServiceNow API origins. Issue polling reads remote status.
Credentials come from the configured environment variable. Redirects are refused,
response bodies and tokens are not logged, and offline mode refuses serving.
Only queue content approved for the destination; no automatic source upload occurs.

## Live deployment inventory

`inventory --collect-kubernetes --network allow-all` invokes installed `kubectl`
with the current context and operator credentials to read pods across namespaces.
Offline mode refuses live collection; `--pods` reads an existing local export.
Only inventory JSON is retained; reports include namespace/pod/service-account
identities and image digests. Treat exports as sensitive infrastructure data.

## Authorization matrix tests

`dast-auth` requires explicit allow-all networking and sends separate bearer
credentials for the configured test actors to GET paths under the supplied base
URL. It never redirects or replays cookies. HTTPS is required except literal
loopback fixtures. Response JSON is checked in memory against the local contract;
response bodies and expected values are not written to reports. Offline refuses
all requests. Use operator-approved staging records, paths and accounts.

## Explicit remediation publication

`fix-pr --publish` requires allow-all networking and uses operator-configured Git
remotes plus installed GitHub/GitLab CLI authentication to push a branch and
create a PR/MR. Only explicit publication performs remote writes. Local test
commands are operator-trusted executables, not network-sandboxed by Securock.

## Secret enforcement exceptions

`protect --server ... --network allow-all` reads approved exception metadata
from the configured HTTPS control-plane origin (literal loopback HTTP is permitted
for tests). No matched secrets or Git blobs are sent. Offline protection is local
and cannot fetch online exceptions. Git receive quarantine variables are inherited;
lazy fetch and interactive Git prompts are disabled.

## Explicit credential operations

`credential` sends an environment-supplied token to api.github.com, gitlab.com,
or the explicit HTTPS `--origin` for check/revoke/rotate. It requires allow-all
and refuses offline; redirects are disabled. GitHub OAuth mutation also sends
the owning app's client credentials. Checks do not imply mutation; revoke and
rotate require their explicit action. Replacement tokens go only to an exclusive
private local file. No scanned source token is submitted automatically.

## OIDC browser authentication

Explicit `serve --sso ... --network allow-all` redirects users to the pinned IdP
authorization endpoint and exchanges a one-time code at the pinned HTTPS token
endpoint. Client secrets, code verifiers and tokens are not logged. Token-endpoint
redirects are refused. Session tokens stay in process memory; no browser storage
is used. Public URL and callback URLs must match the operator's approved service
origin. Offline mode cannot enable this network service.

## Management request logging

Service access logs contain peer IP, authenticated subject/tenant, normalized
route, status and time. Raw URLs/queries/object IDs, bodies, tokens and cookies
are not logged. Logs go to the operator's stderr collector; configure its region,
access controls, deletion and retention separately from encrypted application state.

## Explicit stateful DAST scenarios

`dast-scenario` requires allow-all networking and HTTPS (or loopback HTTP for
local fixtures). It executes only listed same-origin HTTP operations; writes
require `--allow-mutations`. Environment-supplied bodies and bearer tokens,
cookies and captured JSON strings remain in memory. Reports identify the origin
and scenario step, without paths containing captures or response contents.
Redirects are not followed, bodies are capped at 1 MiB, and each scenario is
bounded to 100 requests and two minutes. Use an authorized test deployment.

## Public release metadata

For dependencies already admitted by the network policy, Securock queries
`proxy.golang.org` module-version `.info`, `crates.io/api/v1/crates/NAME/VERSION`,
and `api.nuget.org` registration/catalog metadata for release dates, licenses
and yanked/deprecated status where available. Only the matching public registry
is supported; private, file, Git and unresolved sources do not use these APIs.
NuGet catalog references stay on the configured registry origin. Offline mode
makes none of these requests. These responses do not establish package signatures
or build provenance, which remain unknown without separate verified evidence.
