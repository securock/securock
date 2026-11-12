# Enterprise deployment and assurance

## Supported deployment boundary

The control plane is a single-instance pilot backend with an encrypted 64 MiB
state limit, not a horizontally scalable database service. Use a private local
filesystem; do not share state across replicas or mount it over a network
filesystem. State backup/recovery, subject binding, key custody and outbound
destinations are operator responsibilities. Deploy only after reviewing this
boundary against the customer's workload and security requirements.

`deploy/securock.service` is a systemd deployment template: non-root dynamic
identity, private state directory, read-only system paths, private temporary
files, no privilege escalation and file-mounted systemd credentials. Install a
reviewed binary at its configured path, replace certificate/IdP paths and verify
on the target systemd host before enabling it. It does not install itself,
provision a certificate, register an IdP or open a firewall. Add SSO/connectors
with an operator-reviewed override and explicit allow-all networking. Keep
secret files root-readable and protect the secret manager's recovery keys.

## Data flow and retention

| Data                           | Processing and destination                          | Operator control                                            |
| ------------------------------ | --------------------------------------------------- | ----------------------------------------------------------- |
| Source                         | Local private runner                                | Read-only project mounts, unprivileged sandbox              |
| Findings and execution records | Runner to configured HTTPS service; encrypted state | Review snippets, tenant permissions, storage region         |
| Identity                       | Pinned IdP; session access tokens in memory         | API audience, MFA, SAML broker, SCIM deprovisioning         |
| Workflow metadata              | Explicit delivery to configured SCM/ticket APIs     | Destination-scoped credentials and redacted descriptions    |
| Access logs                    | Operator stderr collector                           | IP/subject retention, SIEM access and approved region       |
| Audit history                  | Signed state digests and actor/action metadata      | Independent trusted public key and checkpoints              |
| Backups                        | Operator-selected encrypted files                   | Separate keys, retention, tested restore and deletion       |
| Release catalog                | Local private file, not encrypted                   | Customer identifiers, filesystem controls and backup policy |

No generative AI provider is contacted by these features. Adding one requires
a separate data-flow review and explicit customer configuration. Customer data
is logically separated by tenant; the single backend uses one encryption key.
Per-tenant customer-managed encryption keys and complete on-premises support
validation are outside this implementation.

## Deployment acceptance

1. Verify the exact release binary and existing release provenance. Pin IdP
   issuer, API audience, key IDs and subject-to-tenant roles. Keep at least two
   independently accountable administrators in the initial reviewed configuration.
2. Exercise login, API token expiry, role denial, cross-tenant denial, session
   logout, SCIM deactivation and signed evidence verification in the actual IdP.
   Later membership changes use audited provisioning; startup bindings only
   initialize new state. SCIM supports Users with limited filtering/PATCH, not Groups.
3. Give each worker only its tenant token and approved project mounts. Run it
   in an OS/container sandbox with resource and egress controls. The scanner
   itself is not an operating-system sandbox.
4. Validate each provider connector with an isolated repository/ticket project
   and read/write scopes limited to it. Exercise rate limits, expired credentials,
   duplicate IDs and uncertain-write reconciliation before enabling real delivery.
5. Use representative customer ground-truth fixtures with `quality`, measure
   scan latency/resource consumption and review coverage gaps. Pilot fixture
   accuracy is not independent proof of coverage for every language/framework.
6. Agree availability/support targets, retention, incident contacts and recovery
   objectives from measured deployments. Rehearse restore before promising an SLA.

## Backup, recovery and keys

Stop serving and workers. Create an encrypted backup using `control`; move it
to the approved backup location. Independently retain the last tenant audit
sequence/digest and the trusted signing public key. Restore to an absent
directory, authenticate encryption and signed state, compare checkpoints, then
run tenant-isolation and login checks before resuming. Test missing/corrupt
backups and unavailable keys; document actual recovery duration and data loss.

Do not delete `instance.lock` until the old process is confirmed stopped. A
crash between initial state creation and audit initialization requires operator
review of the still-uninitialized state; missing checkpoints are not silently
trusted. Fully valid older backups still need external checkpoints to detect
rollback. File sync and atomic rename protect process-crash recovery; qualify
power-loss durability on the target filesystem separately.

Key rotation must be planned: the current store does not expose automatic
encryption/signing rekeying or a multi-key historical trust registry. Keep the
existing keys available for historical restore; provision a reviewed migration
before retiring them. No software command can recover a lost encryption key.

## Incident handling and security review

For suspected exposure, disable the affected IdP subject/credential, suspend
workers and connector writes, preserve encrypted state and independently
retained audit checkpoints, and investigate normalized access logs. Rotate
provider credentials through their supported workflow and update dependent
consumers. Document affected tenants, data categories, timeline, containment
and customer/regulator notifications required by contract and applicable law.

Use the repository's SECURITY.md for vulnerability reporting. Before production
procurement, obtain an independent penetration test covering tenant isolation,
authorization, OAuth/session handling, provisioning and worker boundaries.
Track remediation and retest evidence. Use OWASP ASVS and MVSP as review
requirements; this repository does not claim an ASVS certification, SOC 2
report, ISO 27001 certification or an independently audited production SLA.

## Integration and analysis limits

- Real enterprise IdP/cloud/provider interoperability requires customer-specific
  credentials and test environments. Local TLS/HTTP fixtures are not that proof.
- Kubernetes collection records pod/container identities. Effective cloud IAM,
  network reachability, data access and non-Kubernetes runtime collectors remain
  explicit unknowns; source annotations do not establish build provenance.
- Release signatures authenticate the trusted signer's claims, not a SLSA
  builder guarantee. Advisory impact input uses exact versioned purls, not
  automatic version-range expansion or live threat intelligence.
- Automatic fixes cover literal Go `InsecureSkipVerify`, Python HTTP-client
  `verify=False` and JavaScript/TypeScript `rejectUnauthorized: false` settings. Tests and source
  rechecks precede optional PR publication; human review remains necessary.
- Secret detection is pattern-based and limited to supported text. Provider
  validity/revocation/rotation requires explicit operator actions and scopes.

## Verification evidence

Automated Go fixtures cover OIDC rejection cases, tenant isolation, provisioning
revocation, PKCE/state/nonce and CSRF, lease cancellation, approval separation,
signed-state recovery, provider request adapters/reconciliation, credential
redaction, source fix verification, release/SBOM binding and accuracy labels.
The local browser scenario exercises organization login, a private scan runner,
shared assignment, tenant denial, logout and authenticated backup/restore.
Retain CI results and customer PoC evidence alongside this control description.

Parser resilience checks can be reproduced with:

```bash
go test -fuzz=FuzzVerifyAccessToken -fuzztime=30s -parallel=2 ./internal/identity
go test -fuzz=FuzzAuthorizationMatrix -fuzztime=30s -parallel=2 ./internal/dast
```

These exercise malformed access tokens and authorization contracts without
contacting an identity provider or application. They complement role/isolation
tests and do not replace a penetration test of a real deployment.
