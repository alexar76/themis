"""Issue the attestations THEMIS can verify offline.

    python attest.py evidence --kind sbom --url https://x/sbom.json --sha256 <hex>
    python attest.py permissions --dossier examples/safe_candidate.json

Both subcommands print a JSON object you paste into the dossier. Signing uses
this deployment's persistent provider identity, so an evidence attestation
issued here is a *self* attestation: strong enough to be non-repudiable, and
deliberately distinguishable from an independent auditor's signature in the
report's ``attestations`` block.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import attestations
from models import AuditInput
from provider_signing import ProviderSigner


def _emit(signer: ProviderSigner, message: bytes) -> int:
    print(
        json.dumps(
            {
                "issuer": signer.public_key_b64,
                "signature": base64.b64encode(signer.private.sign(message)).decode(),
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="statement", required=True)

    evidence = sub.add_parser("evidence", help="attest one evidence artifact")
    evidence.add_argument("--kind", required=True)
    evidence.add_argument("--url", required=True)
    evidence.add_argument("--sha256", required=True)

    permissions = sub.add_parser("permissions", help="sign a dossier's own declaration")
    permissions.add_argument("--dossier", required=True, type=Path)

    args = parser.parse_args(argv)
    signer = ProviderSigner()

    if args.statement == "evidence":
        if len(args.sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in args.sha256):
            print("--sha256 must be a 64-character hex digest", file=sys.stderr)
            return 2
        return _emit(
            signer, attestations.evidence_message(args.kind, args.url, args.sha256)
        )

    try:
        envelope = json.loads(args.dossier.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"cannot read dossier: {exc}", file=sys.stderr)
        return 2
    payload = envelope.get("input", envelope)
    try:
        parsed = AuditInput.model_validate(payload)
    except ValueError as exc:
        print(f"dossier is not a valid audit input: {exc}", file=sys.stderr)
        return 2
    return _emit(
        signer,
        attestations.permissions_message(
            product_id=parsed.candidate.product_id,
            publisher_id=parsed.candidate.publisher_id,
            permissions=parsed.permissions.model_dump(),
        ),
    )


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main())
