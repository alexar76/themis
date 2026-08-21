<!-- aicom-mirror-notice -->
> **📖 Read-only mirror.** `themis` is published from the canonical AI-Factory monorepo.
> **Pull requests are not accepted** — any commit pushed here is overwritten by
> `scripts/mirror_satellites.sh` on the next sync.
> 🐞 Found a bug or have a request? Please **[open an issue](https://github.com/alexar76/themis/issues)**.

# THEMIS

<!-- aicom-readme-badges -->
<p align="center">
  <a href="https://github.com/alexar76/themis/actions/workflows/test.yml"><img src="https://github.com/alexar76/themis/actions/workflows/test.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-3776AB" alt="Python >=3.11" />
  <img src="https://img.shields.io/badge/tests-84%20passing-4c1" alt="84 tests passing" />
  <img src="https://img.shields.io/badge/coverage-98%25%2B-4c1" alt="Coverage above 98%" />
  <img src="https://img.shields.io/badge/docs-EN%20RU%20ES%20FR%20ZH-9c70ff" alt="Documentation in 5 languages" />
  <img src="https://img.shields.io/badge/AIMarket-Protocol%20v2-35e7ff" alt="AIMarket Protocol v2" />
  <img src="https://img.shields.io/badge/OWASP-Agentic%20Top%2010-ff5577" alt="OWASP Agentic Top 10 mapped" />
  <img src="https://img.shields.io/badge/signing-Ed25519-8d83ff" alt="Ed25519 signing" />
  <a href="https://github.com/alexar76/themis/blob/main/LICENSE"><img src="https://raw.githubusercontent.com/alexar76/themis/main/docs/badges/license.svg" alt="License: MIT" /></a>
</p>
<!-- /aicom-readme-badges -->

<p align="center">
  <img src="docs/screenshots/hero.jpg" alt="THEMIS — publish-time admission gate for AIMarket" width="900">
  <br>
  <sub><b>Should this AI agent be allowed into your business?</b> —
    <a href="https://alexar76.github.io/themis/"><b>landing →</b></a> ·
    <a href="#quick-start"><b>run locally →</b></a> ·
    <a href="https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/themis.en.md"><b>full tutorial →</b></a> ·
    <a href="https://github.com/alexar76/aicom/blob/main/docs/ecosystem/supply-chain-admission.md"><b>Hub admission →</b></a>
  </sub>
</p>

<p align="center">
  <strong>THEMIS</strong> (Θέμις) — publish-time <strong>admission gate</strong> for AIMarket<br>
  Signed <code>approve</code> / <code>review</code> / <code>reject</code> · not Metis cognition · not WARDEN runtime
</p>

<p align="center">
  <a href="README.md"><b>English</b></a> ·
  <a href="docs/README.ru.md">Русский</a> ·
  <a href="docs/README.es.md">Español</a> ·
  <a href="docs/README.fr.md">Français</a> ·
  <a href="docs/README.zh.md">中文</a> ·
  <a href="https://github.com/alexar76/aicom/blob/main/docs/localization-glossary.md">Localization glossary</a>
</p>

## Gallery

Receipt cards and role split below are grounded in a live local `/invoke` against
`examples/safe_candidate.json` (**approve**, score `100`) and a fail-closed mutation
(**reject**, HTTPS + permissions findings). Capability id:
`agent.security.supply-chain.audit@v1`.

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/report-approve.jpg" alt="THEMIS admission receipt — APPROVE"></td>
    <td width="50%"><img src="docs/screenshots/report-reject.jpg" alt="THEMIS admission receipt — REJECT"></td>
  </tr>
  <tr>
    <td align="center"><strong>Approve · score 100 · risk_tier low</strong></td>
    <td align="center"><strong>Reject · fail-closed findings</strong></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/invoke-approve.svg" alt="Raw live /invoke approve JSON"></td>
    <td width="50%"><img src="docs/screenshots/invoke-reject.svg" alt="Raw live /invoke reject JSON"></td>
  </tr>
  <tr>
    <td align="center"><strong>Raw signed /invoke · approve</strong></td>
    <td align="center"><strong>Raw signed /invoke · reject</strong></td>
  </tr>
  <tr>
    <td colspan="2" align="center">
      <img src="docs/screenshots/roles-split.jpg" alt="THEMIS vs WARDEN vs Metis role split" width="900">
    </td>
  </tr>
  <tr>
    <td colspan="2" align="center"><strong>THEMIS admits · WARDEN gates invoke · Metis advises</strong></td>
  </tr>
</table>

## Why this agent

Businesses are adding agents to real workflows, while the agent itself may execute code, read
secrets, spend money, write to external systems, or call an unreviewed dependency. The
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
now explicitly includes identity and privilege abuse, **AI-agent supply chain** vulnerabilities,
insecure inter-agent communication, cascading failures, and human-agent trust exploitation.

This reference agent turns a candidate AIMarket manifest, declared permissions, evidence, expected
usage, and a buyer policy into one bounded report:

- `approve`, `review`, or `reject`;
- a deterministic score and risk tier;
- projected monthly cost;
- specific findings and remediations;
- OWASP Agentic risk mappings;
- an optional asynchronous Metis second opinion;
- a request-bound Ed25519 signature (receipt).

It does **not** certify compliance or predict future behaviour. It helps a human make a better
procurement decision from explicit evidence — and, when Hub admission mode is enabled, it is the
**publish admission** check before a third-party capability enters the public catalogue.

Listing on Hub is already multi-layer (operator publish token, stake, manifest, signatures, trust
floors) — **not** open signup. Consuming the ecosystem via ARGUS / `aimarket-mcp` does not require
THEMIS. See [supply-chain admission](https://github.com/alexar76/aicom/blob/main/docs/ecosystem/supply-chain-admission.md).

## Golden path

```text
candidate manifest + permissions + evidence + usage + policy
                              │
                              ▼
                 deterministic policy engine
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
 signed decision immediately          lazy Metis advisory job
 approve / review / reject             pending → completed
```

Metis never overrides the deterministic decision. It reviews the consistency of the report, not
the truth or future safety of the candidate agent.

## Quick start

```bash
git clone https://github.com/alexar76/themis.git
cd themis
uv sync --extra dev
uv run python configure_provider.py
uv run python -m pytest -q
uv run python agent.py
```

In another terminal:

```bash
curl --fail-with-body -sS \
  -X POST http://127.0.0.1:8080/invoke \
  -H 'Content-Type: application/json' \
  --data-binary @examples/safe_candidate.json
```

The safe sample returns `decision: approve`. Try changing its `invoke_url` to public HTTP or enable
`execute_code` without human approval and observe a fail-closed rejection.

## Input contract

| Block | Meaning |
|---|---|
| `candidate` | AIMarket manifest being considered |
| `permissions` | Declared powers: code, secrets, money, writes, network, personal data |
| `evidence` | HTTPS references such as an SBOM, security policy, or independent audit |
| `usage` | Expected call volume and data classification |
| `policy` | Buyer's price, budget, identity, evidence, and verification requirements |
| `request_metis` | Start an advisory Metis job without blocking the main decision |

All models reject unknown fields. The service never fetches evidence URLs, so untrusted input cannot
turn it into an SSRF proxy.

## Lazy Metis status

Copy `.env.example` to `.env` and set `METIS_API_KEY` on the server. Do not send it from a browser.
With `request_metis: true`, `/invoke` returns immediately:

```json
{
  "metis": {
    "status": "pending",
    "verification_id": "...",
    "poll_url": "/verification/..."
  }
}
```

Poll `GET /verification/{verification_id}` until `completed`, `not_performed`, `timeout`,
`unavailable`, or `failed`. Jobs are memory-bounded and expire; upstream errors are reduced to an
allowlisted reason rather than leaking infrastructure details.

## Security boundary

- request bodies are bounded to 256 KiB;
- duplicate JSON keys and unknown fields are rejected;
- candidate URLs are parsed but never contacted;
- evidence references are never fetched;
- the provider identity is a persistent Ed25519 key stored with mode `0600`;
- the response signature covers the exact submitted input and result;
- Metis credentials remain server-side;
- Metis jobs have hard capacity, concurrency, response-size, timeout, and TTL bounds;
- Python dependencies are locked in `uv.lock`, including the Docker image build;
- OpenAPI, Swagger, and ReDoc routes are disabled;
- the Docker image runs as an unprivileged user and expects a persistent key volume;
- direct callers are not authenticated or billed: keep the port private behind Hub and HTTPS ingress.

See [SECURITY.md](SECURITY.md) and [the architecture](docs/ARCHITECTURE.md).

## Publish to Hub

Replace `invoke_url` with the deployed HTTPS endpoint and set a stable `publisher_id`, then:

```bash
uv run python configure_provider.py
uv run python validate_manifest.py
aimarket publish capability.json --hub https://modelmarket.dev
```

Publishing remains an explicit operator action because Hub identity, stake, trust policy, and
production reachability cannot safely be inferred by a project generator.

## Alien Monitor

After Hub registration and a real Hub invoke, admission telemetry appears on the Alien Monitor
**THEMIS** node (dossier-free receipts from Hub `GET /supply/audits`). This repository does not
inject its own permanent 3D node from an unauthenticated client.

## Learn by rebuilding it

The five-language lesson starts from the actual command below and recreates this repository step by
step:

```bash
uvx create-aimarket-agent themis --kind tool --metis
```

[Open the complete English tutorial](https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/themis.en.md).

## License

MIT. OWASP names and identifiers are used for mapping and remain property of their respective owner.
