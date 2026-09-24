"""Capture real signed receipts so the published console has something true to show.

    python docs/landing/console/build_bundle.py            # against 127.0.0.1:8080
    python docs/landing/console/build_bundle.py --port 8099

The console published beside the landing page has no agent behind it. Rather
than mocking a verdict — which would make the one interesting claim (that a
receipt is signed and re-checkable) a lie — this walks the bundled dossiers
through a running agent and stores the exact response bytes.

The raw text matters: the signature covers the canonical form of what the agent
returned, and Python prints a float as ``20.0`` where JavaScript prints ``20``.
Re-serialising a parsed copy would break verification in the browser, so both
the request and the response are kept verbatim.

No key material is captured — only the public key the console verifies against.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

SCENARIOS = (
    ("attested", "Attested example", "attested_candidate.json"),
    ("safe", "Safe example", "safe_candidate.json"),
    ("unsafe", "Unsafe example", "unsafe_candidate.json"),
)


def _post(base: str, body: bytes) -> tuple[str, str]:
    request = urllib.request.Request(
        f"{base}/invoke", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        text = response.read().decode("utf-8")
        signature = response.headers.get("X-Provider-Signature", "")
    if not signature:
        raise RuntimeError("agent returned no X-Provider-Signature")
    return text, signature


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    base = f"http://{args.host}:{args.port}"

    try:
        with urllib.request.urlopen(f"{base}/health", timeout=10) as response:
            health = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"no agent on {base}: {exc}", file=sys.stderr)
        print("start it first:  uv run python agent.py", file=sys.stderr)
        return 2

    scenarios = []
    for scenario_id, label, filename in SCENARIOS:
        source = ROOT / "examples" / filename
        submitted_text = source.read_text(encoding="utf-8")
        receipt_text, signature = _post(base, submitted_text.encode("utf-8"))
        decision = json.loads(receipt_text)["result"]["decision"]
        scenarios.append(
            {
                "id": scenario_id,
                "label": label,
                "decision": decision,
                "submitted_text": submitted_text,
                "receipt_text": receipt_text,
                "signature": signature,
            }
        )
        print(f"{scenario_id:9s} → {decision}")

    bundle = {
        "note": (
            "Receipts signed by a real THEMIS agent. Verified in the browser against "
            "provider_pubkey below. Regenerate with docs/landing/console/build_bundle.py."
        ),
        "provider_pubkey": health["provider_pubkey"],
        "agent": {
            key: health[key]
            for key in ("agent", "kind", "metis_configured", "metis_job_store", "metis_job_store_shared")
            if key in health
        },
        "scenarios": scenarios,
    }
    out = HERE / "receipts.json"
    out.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":  # pragma: no cover - operator tool
    raise SystemExit(main())
