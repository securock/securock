# Vendored schemas

Official JSON schemas, kept only so the tests can check that the SBOM and VEX documents
securock writes are valid. They are not used at run time and are not modified.

| File | What | Source | License |
| --- | --- | --- | --- |
| `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json` | CycloneDX 1.6 | https://github.com/CycloneDX/specification (`schema/`) | Apache-2.0 |
| `spdx-schema.json` | SPDX 2.3 | https://github.com/spdx/spdx-spec (`support/2.3`, `schemas/`) | CC-BY-3.0 / Apache-2.0 |
| `openvex_json_schema.json` | OpenVEX 0.2.0 | https://github.com/openvex/spec | Apache-2.0 |

To update one, download the file from the repository above at the version securock targets.
