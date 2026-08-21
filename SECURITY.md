# Security policy

## Supported version

Security fixes target the latest `main` branch until a stable release line is announced.

## Report privately

Do not open a public issue for a vulnerability. Use GitHub private vulnerability reporting in
`alexar76/themis` and include the affected revision, reproduction, impact, and a
minimal non-sensitive proof.

Never include Metis API keys, provider seeds, Hub publish tokens, customer manifests, or personal
data in a report.

## Trust boundaries

- `candidate`, `permissions`, `evidence`, `usage`, and `policy` are untrusted input.
- Evidence URLs are inert references. The service never fetches them.
- A signed report proves which provider produced that report for a specific input; it does not prove
  that a candidate is safe or that its evidence is true.
- Metis is advisory and cannot change the deterministic procurement decision.
- `/invoke` rejects bodies larger than 256 KiB, duplicate JSON keys, and unknown model fields.
- Evidence URLs are never fetched, so candidate input cannot turn the service into an SSRF proxy.
- Ed25519 signatures bind a result to the exact decoded input and provider identity.
- Hub or an authenticated ingress owns caller authentication, billing, rate limiting, and public abuse
  controls.
- A production operator owns key backup, publisher identity, stake, TLS, logging policy, and incident
  response.

## Deployment checklist

1. Keep the container port on loopback or a private network.
2. Put an authenticated HTTPS ingress or AIMarket Hub in front of `/invoke`.
3. Mount one persistent `/data/provider.key`; never bake the seed into an image.
4. Back up the key before publishing `provider_pubkey`.
5. Provide `METIS_API_KEY` only through a server-side secret manager.
6. Apply an external request rate limit and concurrency limit.
7. Avoid logging request bodies: dossiers may contain sensitive business metadata.
8. Pin the image digest and rerun the test suite before deployment.

## Attestation boundary

Evidence and permission attestations are verified **offline**: the signature is checked against a
canonical statement built from fields already present in the dossier. Nothing is fetched, so the
attestation path cannot be turned into an SSRF primitive either.

- an attestation without a digest is rejected — there is no artifact to bind a signature to;
- non-canonical base64, wrong key or signature length, and points off the curve all fail closed;
- a signature that fails to verify is reported (`evidence.attestation_invalid`,
  `permissions.declaration_signature_invalid`); a missing one is scored only when the buyer's
  policy requires it, so a forged proof is always treated as worse than an absent one;
- `trusted_evidence_issuers` is buyer policy, never taken from the candidate.

## Replica boundary

Metis job status lives in process memory by default. A poll routed to another replica cannot see a
job it never accepted, so `METIS_JOB_STORE=memory` is single-replica only. `METIS_JOB_DB` points the
store at a shared volume (SQLite, WAL, wall-clock TTL) and makes the job cap global; declaring
`THEMIS_REPLICAS>1` without a shared store refuses to start rather than silently losing polls.
