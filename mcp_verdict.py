"""MCP install decisions over one verified, fresh HISTOR snapshot.

Policy themis-mcp/2 refuses approval when required evidence is absent, stale,
incomplete or bound to another tool set/version. The signed snapshot, including
all package findings, is returned verbatim with the decision. Remote MCP tools
are never invoked by this service.
"""

from __future__ import annotations

import base64
import os
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from awr import canonicalize, parse_did_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MCP_CAPABILITY_ID = "agent.security.mcp.verdict@v1"
POLICY = "themis-mcp/2"
MAX_AGE = timedelta(days=2)
HISTOR_URL = os.getenv("THEMIS_HISTOR_URL", "https://histor.modelmarket.dev").rstrip("/")
CACHE_TTL_S = 600
RECENT_DAYS = 30
PACKAGE = re.compile(r"^(npm:(@[a-z0-9][a-z0-9._~-]{0,100}/)?[a-z0-9][a-z0-9._~-]{0,100}|pypi:[A-Za-z0-9][A-Za-z0-9._-]{0,126})$")
SEVERITY_ORDER = ("reject", "review", "unknown", "note")


class BadQuery(ValueError):
    pass


def parse_query(package: str | None, endpoint: str | None) -> dict[str, str]:
    if bool(package) == bool(endpoint):
        raise BadQuery("send exactly one of package (npm:<name>, pypi:<name>) or endpoint (https://…)")
    if package:
        if not PACKAGE.match(package):
            raise BadQuery("package must be npm:<name> or pypi:<name>")
        return {"package": package}
    assert endpoint is not None
    if len(endpoint) > 2000 or not endpoint.startswith("https://") or any(c.isspace() for c in endpoint):
        raise BadQuery("endpoint must be an https URL")
    return {"endpoint": endpoint}


def fetch_evidence(query: dict[str, str], client: httpx.Client) -> dict[str, Any]:
    """Trust only the configured issuer, or key discovery at the configured HTTPS origin.

    A key supplied by the signed payload itself is never its own trust anchor.
    Redirects are refused and the exact requested subject and timestamp are verified.
    """
    if not HISTOR_URL.startswith("https://"):
        raise ValueError("HISTOR evidence requires HTTPS")
    did = os.getenv("THEMIS_HISTOR_ISSUER_DID")
    if not did:
        issuer = client.get(f"{HISTOR_URL}/api/v1/issuer", follow_redirects=False)
        issuer.raise_for_status()
        did = issuer.json()["did"]
    check = client.post(f"{HISTOR_URL}/api/v1/check", json=query, follow_redirects=False)
    check.raise_for_status()
    answer = check.json()
    signature = answer.get("signature") or {}
    if (answer.get("type") != "histor.check/v1" or answer.get("issuer") != did
            or signature.get("alg") != "Ed25519"
            or signature.get("verificationMethod") != f"{did}#{did.split(':')[-1]}"):
        raise ValueError("invalid HISTOR signer or document type")
    value = signature.get("value", "")
    Ed25519PublicKey.from_public_bytes(parse_did_key(did)).verify(
        base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True),
        canonicalize({k: v for k, v in answer.items() if k != "signature"}))
    if any((answer.get("query") or {}).get(k) != v for k, v in query.items()):
        raise ValueError("HISTOR evidence belongs to another query")
    return answer


def decide(answer: dict[str, Any], server: dict[str, Any] | None = None, *, now: datetime | None = None) -> dict[str, Any]:
    reasons: list[dict[str, str]] = []
    now = now or datetime.now(UTC)

    def reason(code: str, severity: str, detail: str) -> None:
        reasons.append({"code": code, "severity": severity, "detail": detail[:400]})

    look = answer.get("packageLookalike")
    if isinstance(look, dict) and look.get("of"):
        reason("LOOKALIKE", "review", f"named like {look['of']} ({look.get('weekly', 0)} downloads a week; this one: "
               f"{look.get('ownWeekly', 0)}) — {look.get('how', 'a similar name')}")
    target = answer.get("target") if isinstance(answer.get("target"), dict) else None
    observed = answer.get("observed") or {}
    scan = answer.get("patternScan") or {}
    classifier = answer.get("classifier") or {}
    s = target or {}
    digest = observed.get("toolSetDigest")
    stamp = _when(answer.get("checkedAt"))
    if not stamp or not timedelta(seconds=-60) <= now - stamp <= timedelta(minutes=15):
        reason("STALE_CHECK", "unknown", "signed check is missing, stale or future-dated")
    if not target:
        reason("NOT_LISTED", "unknown", "HISTOR has no record of this server or package")
    elif not digest:
        reason("NOT_OBSERVED", "unknown", "HISTOR has not read its tools")
    else:
        last = _when(observed.get("lastObserved"))
        if s.get("lastStatus") != "ok" or not last or not timedelta(seconds=-60) <= now - last <= MAX_AGE:
            reason("OBSERVATION_INCOMPLETE", "unknown", "latest read failed or last successful observation is stale")
        if s.get("listed") is not True:
            reason("DELISTED", "review", "the target is no longer listed")
        if scan.get("status") != "scanned" or scan.get("toolSetDigest") != digest or not scan.get("patternSet") or not all(type(scan.get(k)) is int for k in ("block", "advise")):
            reason("PATTERN_COVERAGE_MISSING", "unknown", "no bound, completed pattern scan")
        else:
            if scan["block"]:
                reason("BLOCK_TIER_PATTERNS", "reject", f"{scan['block']} block-tier WARDEN matches")
            if scan["advise"]:
                reason("ADVISE_TIER_PATTERNS", "review", f"{scan['advise']} advise-tier WARDEN matches")
        count = observed.get("toolCount")
        classified_at = _when(classifier.get("classifiedAt"))
        if (classifier.get("status") != "classified" or classifier.get("toolSetDigest") != digest
                or type(count) is not int or classifier.get("checkedTools") != count or classifier.get("toolCount") != count
                or classifier.get("truncatedTools") != 0 or type(classifier.get("flagged")) is not int
                or not classified_at or not timedelta(seconds=-60) <= now - classified_at <= MAX_AGE):
            reason("CLASSIFIER_COVERAGE_MISSING", "unknown", "no fresh, complete classifier inspection of this tool set")
        elif classifier["flagged"]:
            reason("CLASSIFIER_FLAGS", "review", f"classifier flagged {classifier['flagged']} tools")
        changed = _when(observed.get("unchangedSince"))
        if observed.get("changes") and changed and changed >= now - timedelta(days=RECENT_DAYS):
            reason("RECENT_CHANGE", "review", "tool definitions changed within the last 30 days")
    sig = s.get("packageSignals") if isinstance(s.get("packageSignals"), dict) else {}
    flags = [f for f in sig.get("flags") or [] if isinstance(f, str)]
    for flag, text in (("provenance-lost", "the registry stopped reporting provenance that was present for the previous version"),
                       ("publisher-changed", "the version was published by someone else than the previous one"),
                       ("install-scripts-added", "the version added install scripts")):
        if flag in flags:
            reason(flag.upper().replace("-", "_"), "review", text)
    if "new-dependencies" in flags:
        reason("NEW_DEPENDENCIES", "note", "the version added dependencies: " + ", ".join(str(d) for d in (sig.get("newDependencies") or [])[:8]))
    behaviour = sig.get("behaviour") if isinstance(sig.get("behaviour"), dict) else {}
    for phase, label in (("installScripts", "its install scripts"), ("startup", "at startup"), ("calls", "when its tools were called")):
        b = behaviour.get(phase) if isinstance(behaviour.get(phase), dict) else {}
        secrets = [d for d in b.get("decoys") or [] if isinstance(d, str)]
        if secrets:
            reason("READS_SECRETS", "reject", f"in HISTOR's sandbox it opened decoy credentials {label}: {', '.join(secrets[:6])}")
        if b.get("decoyTransmitted"):
            reason("DECOY_TRANSMITTED", "reject", "a synthetic secret was sent to the protocol trap")
        if b.get("unexpectedRecipients"):
            reason("UNEXPECTED_RECIPIENT", "reject", "synthetic input was copied to an unrequested recipient: " + ", ".join(map(str, b["unexpectedRecipients"][:6])))
        if b.get("writes"):
            reason("PERSISTENCE", "reject", f"in HISTOR's sandbox it wrote {label} where it would outlive the session: {', '.join(map(str, b['writes'][:4]))}")
    if str(s.get("endpoint", "")).startswith(("npm:", "pypi:")):
        if sig.get("metadataComplete") is not True or sig.get("version") != s.get("packageVersion"):
            reason("PACKAGE_METADATA_INCOMPLETE", "unknown", "package metadata is missing or belongs to another version")
        if sig.get("provenanceVerified") is not True:
            reason("BUILD_UNVERIFIED", "unknown", "attestation presence alone does not verify the installed artifact")
        if behaviour.get("complete") is not True or behaviour.get("version") != s.get("packageVersion") or not all(behaviour.get(p, {}).get("complete") is True for p in ("installScripts", "startup", "calls")):
            reason("BEHAVIOUR_INCOMPLETE", "unknown", "sandbox coverage is missing, incomplete or for another version")
    calls = behaviour.get("calls") or {}
    if calls.get("network") or calls.get("lookups"):
        reason("CALL_NETWORK", "review", "tool calls attempted network access; destinations and payloads require review")
    if "dependency-specs-changed" in flags:
        reason("DEPENDENCY_SPECS_CHANGED", "review", "existing dependency constraints changed")
    start = behaviour.get("startup") if isinstance(behaviour.get("startup"), dict) else {}
    if start.get("network") or start.get("lookups"):
        reason("STARTUP_NETWORK", "review", "it reached out at startup, before any tool was called: " + ", ".join(map(str, (start.get("network") or start.get("lookups"))[:6])))
    scripts = behaviour.get("installScripts") if isinstance(behaviour.get("installScripts"), dict) else {}
    if scripts.get("network") or scripts.get("lookups"):
        reason("INSTALL_NETWORK", "review", "its install scripts reach " + ", ".join(map(str, (scripts.get("network") or scripts.get("lookups"))[:6])))
    severities = {r["severity"] for r in reasons}
    decision = next((level for level in ("reject", "review", "unknown") if level in severities), "approve")
    reasons.sort(key=lambda r: SEVERITY_ORDER.index(r["severity"]))
    return {"decision": decision, "reasons": reasons}


def _when(text: Any) -> datetime | None:
    try:
        return datetime.strptime(str(text)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


class VerdictCache:
    """HISTOR rate-limits per address; THEMIS asks for many people, so answers are kept a while."""

    def __init__(self, ttl_s: float = CACHE_TTL_S, size: int = 2048) -> None:
        self.ttl_s, self.size = ttl_s, size
        self.items: dict[str, tuple[float, dict[str, Any]]] = {}
        self.lock = threading.Lock()

    def get(self, key: str) -> dict[str, Any] | None:
        with self.lock:
            hit = self.items.get(key)
            return hit[1] if hit and time.monotonic() - hit[0] < self.ttl_s else None

    def put(self, key: str, value: dict[str, Any]) -> None:
        with self.lock:
            if len(self.items) >= self.size:
                self.items.pop(next(iter(self.items)))
            self.items[key] = (time.monotonic(), value)


def verdict(query: dict[str, str], client: httpx.Client, *, now: datetime | None = None) -> dict[str, Any]:
    answer = fetch_evidence(query, client)
    decided = decide(answer, now=now)
    target = answer.get("target") if isinstance(answer.get("target"), dict) else {}
    return {
        "policy": POLICY,
        "subject": {**query, **({"historTarget": target.get("id"), "page": target.get("page")} if target else {})},
        **decided,
        "decidedAt": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence": {"histor": HISTOR_URL, "check": answer},
        "note": "approve means the required fresh evidence is complete and has no policy findings; it is not a certificate that the server is safe",
    }
