# Architecture

## Components

| File | Responsibility |
|---|---|
| `models.py` | Strict, bounded input contract |
| `auditor.py` | Deterministic findings, score, decision, and safe Metis prompt |
| `metis_advisor.py` | Bounded asynchronous Metis jobs and allowlisted statuses |
| `agent.py` | FastAPI boundary, invoke identity, signing, and status endpoint |
| `provider_signing.py` | Persistent Ed25519 identity and request-bound signatures |
| `validate_manifest.py` | Fail-closed pre-publish validation |

## Decision model

The scoring engine uses fixed severity penalties. A critical finding always rejects the candidate.
High findings require review unless the aggregate penalty already crosses the rejection threshold.
The score is intentionally explainable; it is not a probability and is never labelled confidence.

```text
critical finding OR score < 50  → reject
high finding OR score < policy  → review
otherwise                       → approve
```

## Metis model

Metis receives only a reduced deterministic report: stable ids, decision, score, risk tier, cost,
finding codes, severities, and OWASP mappings. Candidate descriptions and evidence contents are
excluded from the prompt. This limits prompt-injection exposure and avoids transmitting the full
procurement dossier.

`assessment_verified` means Metis verified the quality of its own assessment envelope. It never
means that the candidate agent was independently verified.

## Known limits

- Evidence authenticity is not checked; only reference structure and supplied digests are assessed.
- Runtime behaviour is not observed.
- The permissions block is a declaration by the caller.
- In-memory Metis job state is appropriate for a tutorial and one process. A multi-replica
  deployment needs a shared TTL store and authenticated status access.
- This is not legal, privacy, compliance, or financial advice.

## Primary references

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [Microsoft 2025 Work Trend Index](https://www.microsoft.com/en-us/worklab/work-trend-index/2025-the-year-the-frontier-firm-is-born)
- [AIMarket Protocol v2](https://github.com/alexar76/aimarket-protocol)
- [create-aimarket-agent](https://github.com/alexar76/create-aimarket-agent)

