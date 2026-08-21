# THEMIS verification report

Date: 2026-08-21 · Scope: monorepo `themis/` + Alien Monitor node + publish path.

## 1. Push scripts & co-author strip

| Check | Result |
|-------|--------|
| `scripts/satellite-map.yaml` id `themis` | Present (homepage → Pages after this release) |
| `mirror_satellites.sh` case `themis)` | Present — `export_simple` MIT |
| Gitea gate `sanitize_git_commit_meta.py` | Wired in `push_gitea_monorepo.sh` |
| Satellite mirror sanitize | Wired before commit / force-push |
| Sample strip | `Co-Authored-By: Cursor Agent` removed; human co-author kept |

## 2. Agent functions (local)

Command: `cd themis && uv run python -m pytest -q` + TestClient `/invoke`.

| Claim | Evidence |
|-------|----------|
| 85 tests, ≥95% coverage | **85 passed**, coverage **98%+** |
| Safe candidate → `approve` | `decision=approve`, `score=100`, `risk_tier=low` |
| Capability id | `agent.security.supply-chain.audit@v1` |
| Fail-closed on HTTP + code-without-approval | Prior probe: `reject`, findings include `transport.https_required`, `permissions.code_without_approval` |
| Scaffold rails present | `configure_provider.py`, `provider_signing.py`, `validate_manifest.py`, Docker, CI |
| Lesson command | `uvx create-aimarket-agent themis --kind tool --metis` |

## 3. Mini-course quality

Location: `create-aimarket-agent/docs/tutorials/themis.{en,ru,es,fr,zh}.md`

| Check | Result |
|-------|--------|
| Five languages | Yes |
| `<!-- tutorial-contract:v1 -->` | Yes |
| 12-step path scaffold→publish | Yes (EN ~320 lines) |
| `test_docs_i18n` reference tokens | Contract tests present |
| Public URLs after publish | https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/themis.en.md |

## 4. Alien Monitor card parameters

Node `themis` (`themis_layers.py` + `ThemisCard.tsx`):

| Field | Meaning |
|-------|---------|
| `mode` | Hub admission `off` / `advisory` / `enforce` |
| `configured` | Auditor URL/pubkey configured on Hub |
| `simulated` | SIM telemetry (UNI demo when Hub has no admission summary) |
| `latest.decision` | `approve` / `review` / `reject` |
| `latest.score` | Deterministic score |
| `latest.risk_tier` | Risk band |
| `latest.capability_id` | Candidate or gate capability |
| `latest.metis_status` | Async Metis advisory status |
| `recent[]` | Dossier-free audit trail (publisher_id, decision, score, metis) |
| metrics | `audits_total`, `approved`, `review`, `rejected`, `metis_pending` |
| links | **always attached**: `landing` (Pages), `tutorial` (mini-course), `github` (repo) |

Topology: Factory → THEMIS → Metis / Hub / MOMUS.

Live check (2026-08-21): node present on https://magic-ai-factory.com/monitor/ (`/api/topology`); card CTAs point at Pages landing + tutorial + repo.

## 5. Landing

- Source: `themis/docs/landing/index.html`
- Deploy: GitHub Pages workflow → https://alexar76.github.io/themis/
- CTA includes mini-course + `uvx create-aimarket-agent themis --kind tool --metis`

## 6. Residual ops

- Live Monitor UI needs **Alien Monitor redeploy** to pick up card/link/knowledge fixes.
- Hub THEMIS admission mode remains operator-controlled (default `off` until advisory/enforce).
