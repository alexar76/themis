from __future__ import annotations

import base64
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import attestations
from auditor import audit
from models import AuditInput


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
    return private, public


def _sign(private: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(private.sign(message)).decode()


def _attest_evidence(private: Ed25519PrivateKey, public: str, item: dict) -> dict:
    message = attestations.evidence_message(item["kind"], item["url"], item["sha256"])
    return {**item, "attestation": {"issuer": public, "signature": _sign(private, message)}}


def _report(payload: dict) -> dict:
    return audit(AuditInput.model_validate(deepcopy(payload)))


def _codes(report: dict) -> set[str]:
    return {finding["code"] for finding in report["findings"]}


# ─────────────────────────── evidence attestations ───────────────────────────


def test_verified_third_party_attestation_is_recorded_as_independent(safe_payload):
    private, public = _keypair()
    safe_payload["evidence"][1] = _attest_evidence(private, public, safe_payload["evidence"][1])
    report = _report(safe_payload)
    assert report["decision"] == "approve"
    assert report["attestations"]["evidence_verified"] == 1
    assert report["attestations"]["evidence_independently_attested"] is True
    assert not {code for code in _codes(report) if code.startswith("evidence.attestation")}


def test_tampered_statement_is_a_finding_not_a_silent_downgrade(safe_payload):
    private, public = _keypair()
    item = _attest_evidence(private, public, safe_payload["evidence"][1])
    item["url"] = "https://audit.example.com/other-report.pdf"
    safe_payload["evidence"][1] = item
    report = _report(safe_payload)
    assert "evidence.attestation_invalid" in _codes(report)
    assert report["attestations"]["evidence_verified"] == 0


@pytest.mark.parametrize("field,value", [
    ("kind", "sbom"),
    ("sha256", "f" * 64),
])
def test_attestation_covers_every_field_of_the_statement(safe_payload, field, value):
    private, public = _keypair()
    item = _attest_evidence(private, public, safe_payload["evidence"][1])
    item[field] = value
    safe_payload["evidence"][1] = item
    assert "evidence.attestation_invalid" in _codes(_report(safe_payload))


def test_attestation_without_a_digest_cannot_identify_an_artifact(safe_payload):
    private, public = _keypair()
    item = _attest_evidence(private, public, safe_payload["evidence"][1])
    item["sha256"] = None
    safe_payload["evidence"][1] = item
    report = _report(safe_payload)
    assert "evidence.attestation_invalid" in _codes(report)
    assert report["attestations"]["evidence_verified"] == 0


def test_decorative_links_never_satisfy_the_evidence_floor(safe_payload):
    """The published hole: pretty but unverifiable references passing procurement."""
    safe_payload["evidence"] = [
        {"kind": "security_policy", "url": "https://looks-real.example.com/security"},
        {"kind": "independent_audit", "url": "https://looks-real.example.com/audit.pdf"},
        {"kind": "sbom", "url": "https://looks-real.example.com/sbom.json"},
    ]
    report = _report(safe_payload)
    assert "evidence.insufficient" in _codes(report)
    assert report["attestations"]["evidence_counted_kinds"] == []
    assert report["decision"] != "approve"


def test_digest_requirement_can_be_relaxed_deliberately(safe_payload):
    safe_payload["evidence"] = [
        {"kind": "security_policy", "url": "https://agents.example.com/security"},
        {"kind": "independent_audit", "url": "https://audit.example.com/audit.pdf"},
    ]
    safe_payload["policy"]["require_evidence_digests"] = False
    report = _report(safe_payload)
    assert "evidence.insufficient" not in _codes(report)
    assert "evidence.digest_missing" in _codes(report)


def test_untrusted_issuer_does_not_count_toward_the_floor(safe_payload):
    private, public = _keypair()
    _, other = _keypair()
    safe_payload["evidence"] = [
        _attest_evidence(private, public, safe_payload["evidence"][0]),
        _attest_evidence(private, public, safe_payload["evidence"][1]),
    ]
    safe_payload["policy"]["trusted_evidence_issuers"] = [other]
    report = _report(safe_payload)
    assert "evidence.attestation_issuer_untrusted" in _codes(report)
    assert "evidence.insufficient" in _codes(report)


def test_trusted_issuer_allowlist_admits_its_own_keys(safe_payload):
    private, public = _keypair()
    safe_payload["evidence"] = [
        _attest_evidence(private, public, safe_payload["evidence"][0]),
        _attest_evidence(private, public, safe_payload["evidence"][1]),
    ]
    safe_payload["policy"]["trusted_evidence_issuers"] = [public]
    report = _report(safe_payload)
    assert "evidence.attestation_issuer_untrusted" not in _codes(report)
    assert "evidence.insufficient" not in _codes(report)


def test_policy_can_demand_signed_evidence(safe_payload):
    safe_payload["policy"]["require_evidence_attestation"] = True
    report = _report(safe_payload)
    assert "evidence.attestation_required" in _codes(report)
    assert "evidence.insufficient" in _codes(report)


def test_policy_can_demand_an_independent_voucher(safe_payload):
    provider = Ed25519PrivateKey.generate()
    provider_public = base64.b64encode(provider.public_key().public_bytes_raw()).decode()
    safe_payload["candidate"]["provider_pubkey"] = provider_public
    safe_payload["evidence"] = [
        _attest_evidence(provider, provider_public, safe_payload["evidence"][0]),
        _attest_evidence(provider, provider_public, safe_payload["evidence"][1]),
    ]
    safe_payload["policy"]["require_independent_attestation"] = True
    report = _report(safe_payload)
    assert "evidence.self_attested_only" in _codes(report)
    assert report["attestations"]["evidence_independently_attested"] is False


# ────────────────────────── permission attestations ──────────────────────────


def _sign_permissions(private: Ed25519PrivateKey, payload: dict, permissions=None) -> str:
    message = attestations.permissions_message(
        product_id=payload["candidate"]["product_id"],
        publisher_id=payload["candidate"]["publisher_id"],
        permissions=AuditInput.model_validate(deepcopy(payload)).permissions.model_dump()
        if permissions is None
        else permissions,
    )
    return _sign(private, message)


def test_signed_declaration_is_bound_to_the_provider_identity(safe_payload):
    private, public = _keypair()
    safe_payload["candidate"]["provider_pubkey"] = public
    safe_payload["permissions_attestation"] = {
        "issuer": public,
        "signature": _sign_permissions(private, safe_payload),
    }
    report = _report(safe_payload)
    proof = report["attestations"]
    assert (proof["permissions_signed"], proof["permissions_signature_valid"]) == (True, True)
    assert proof["permissions_bound_to_provider_key"] is True
    assert not {code for code in _codes(report) if code.startswith("permissions.declaration")}


def test_a_declaration_signed_over_other_permissions_is_critical(safe_payload):
    private, public = _keypair()
    safe_payload["candidate"]["provider_pubkey"] = public
    lie = {
        "execute_code": False,
        "access_secrets": False,
        "spend_money": False,
        "write_external_systems": False,
        "unrestricted_network": False,
        "read_personal_data": False,
        "human_approval_for_high_impact": True,
    }
    safe_payload["permissions_attestation"] = {
        "issuer": public,
        "signature": _sign_permissions(private, safe_payload, permissions=lie),
    }
    report = _report(safe_payload)
    assert "permissions.declaration_signature_invalid" in _codes(report)
    assert report["decision"] == "reject"


def test_a_declaration_signed_by_a_stranger_is_flagged(safe_payload):
    private, public = _keypair()
    safe_payload["permissions_attestation"] = {
        "issuer": public,
        "signature": _sign_permissions(private, safe_payload),
    }
    report = _report(safe_payload)
    assert "permissions.declaration_issuer_mismatch" in _codes(report)
    assert report["attestations"]["permissions_bound_to_provider_key"] is False


def test_policy_can_demand_a_signed_declaration(safe_payload):
    safe_payload["policy"]["require_permission_attestation"] = True
    report = _report(safe_payload)
    assert "permissions.declaration_unsigned" in _codes(report)
    assert report["attestations"]["permissions_signed"] is False


# ──────────────────────────── primitive hardening ────────────────────────────


def test_baseline_dossier_is_unchanged_by_the_attestation_pass(safe_payload):
    report = _report(safe_payload)
    assert (report["decision"], report["score"], report["findings"]) == ("approve", 100, [])
    assert report["attestations"]["evidence_counted_kinds"] == [
        "independent_audit",
        "privacy_policy",
    ]


@pytest.mark.parametrize("issuer", [
    "",
    "not base64!",
    base64.b64encode(b"short").decode(),
    base64.b64encode(b"k" * 33).decode(),
])
def test_verify_rejects_every_malformed_key(issuer):
    private, _ = _keypair()
    message = b"payload"
    assert attestations.verify(
        issuer=issuer, signature=_sign(private, message), message=message
    ) is False


@pytest.mark.parametrize("signature", ["", "///", base64.b64encode(b"s" * 63).decode()])
def test_verify_rejects_every_malformed_signature(signature):
    _, public = _keypair()
    assert attestations.verify(issuer=public, signature=signature, message=b"x") is False


def test_verify_rejects_non_canonical_base64():
    private, public = _keypair()
    message = b"payload"
    signature = _sign(private, message)
    assert attestations.verify(issuer=public, signature=signature, message=message) is True
    # Same bytes, non-canonical trailing bits: must not be accepted as equivalent.
    mutated = public[:-2] + "/="
    assert attestations.verify(issuer=mutated, signature=signature, message=message) is False


def test_statements_are_canonical_and_domain_separated():
    evidence = attestations.evidence_message("sbom", " https://a/b ", "A" * 64)
    assert b'"statement":"aimarket.evidence.v1"' in evidence
    assert b'"sha256":"' + b"a" * 64 + b'"' in evidence
    assert b'"url":"https://a/b"' in evidence
    permissions = attestations.permissions_message(
        product_id="p", publisher_id="q", permissions={"b": True, "a": False}
    )
    assert permissions.index(b'"a"') < permissions.index(b'"b"')
    assert b'"statement":"aimarket.permissions.v1"' in permissions


# ─────────────────────── runtime violation counter-evidence ───────────────────────


def _violation(private: Ed25519PrivateKey, public: str, payload: dict, permission: str,
               digest: str | None = None) -> dict:
    message = attestations.violation_message(
        capability_id=payload["candidate"]["capability_id"],
        permission=permission,
        permissions_sha256=digest or attestations.permissions_digest(
            AuditInput.model_validate(deepcopy(payload)).permissions.model_dump()
        ),
        product_id=payload["candidate"]["product_id"],
    )
    return {"permission": permission,
            "attestation": {"issuer": public, "signature": _sign(private, message)}}


def test_two_observers_can_falsify_a_declaration(safe_payload):
    """The closure for self-declaration: a denied permission others observed."""
    first, first_key = _keypair()
    second, second_key = _keypair()
    safe_payload["runtime_violations"] = [
        _violation(first, first_key, safe_payload, "spend_money"),
        _violation(second, second_key, safe_payload, "spend_money"),
    ]
    report = _report(safe_payload)
    assert "permissions.declaration_contradicted" in _codes(report)
    assert report["decision"] == "reject"
    assert report["attestations"]["runtime_violations_contradicting"] == ["spend_money"]
    assert report["attestations"]["runtime_violations_verified"] == 2


def test_one_observer_is_visible_but_never_fatal(safe_payload):
    private, public = _keypair()
    safe_payload["runtime_violations"] = [
        _violation(private, public, safe_payload, "execute_code")
    ]
    report = _report(safe_payload)
    assert "permissions.declaration_reported" in _codes(report)
    assert "permissions.declaration_contradicted" not in _codes(report)
    assert report["decision"] != "reject"


def test_the_same_observer_twice_is_still_one_voice(safe_payload):
    private, public = _keypair()
    safe_payload["runtime_violations"] = [
        _violation(private, public, safe_payload, "access_secrets"),
        _violation(private, public, safe_payload, "access_secrets"),
    ]
    report = _report(safe_payload)
    assert "permissions.declaration_contradicted" not in _codes(report)
    assert report["attestations"]["runtime_violations_verified"] == 2


def test_observing_what_was_declared_is_agreement_not_violation(safe_payload):
    first, first_key = _keypair()
    second, second_key = _keypair()
    safe_payload["permissions"]["read_personal_data"] = True
    safe_payload["runtime_violations"] = [
        _violation(first, first_key, safe_payload, "read_personal_data"),
        _violation(second, second_key, safe_payload, "read_personal_data"),
    ]
    report = _report(safe_payload)
    assert not {c for c in _codes(report) if c.startswith("permissions.declaration_")}
    assert report["attestations"]["runtime_violations_contradicting"] == []


def test_a_report_bound_to_another_declaration_does_not_apply(safe_payload):
    """Declaring honestly must retire stale reports rather than brand forever."""
    first, first_key = _keypair()
    second, second_key = _keypair()
    stale = attestations.permissions_digest({"spend_money": False})
    safe_payload["runtime_violations"] = [
        _violation(first, first_key, safe_payload, "spend_money", digest=stale),
        _violation(second, second_key, safe_payload, "spend_money", digest=stale),
    ]
    report = _report(safe_payload)
    assert "permissions.violation_report_invalid" in _codes(report)
    assert "permissions.declaration_contradicted" not in _codes(report)


def test_a_forged_report_is_a_finding_against_the_forger(safe_payload):
    private, public = _keypair()
    report_item = _violation(private, public, safe_payload, "spend_money")
    report_item["permission"] = "unrestricted_network"
    safe_payload["runtime_violations"] = [report_item]
    report = _report(safe_payload)
    assert "permissions.violation_report_invalid" in _codes(report)
    assert report["attestations"]["runtime_violations_verified"] == 0


def test_reporter_threshold_is_buyer_policy(safe_payload):
    private, public = _keypair()
    safe_payload["policy"]["runtime_violation_min_reporters"] = 1
    safe_payload["runtime_violations"] = [
        _violation(private, public, safe_payload, "spend_money")
    ]
    report = _report(safe_payload)
    assert "permissions.declaration_contradicted" in _codes(report)


def test_declaration_digest_is_stable_and_covers_every_flag(safe_payload):
    parsed = AuditInput.model_validate(deepcopy(safe_payload))
    digest = attestations.permissions_digest(parsed.permissions.model_dump())
    assert digest == _report(safe_payload)["attestations"]["permissions_sha256"]
    flipped = deepcopy(safe_payload)
    flipped["permissions"]["spend_money"] = True
    other = AuditInput.model_validate(flipped).permissions.model_dump()
    assert attestations.permissions_digest(other) != digest


# ────────────────────────── wire format is a contract ──────────────────────────
# These byte strings are the interoperability surface: the Hub verifies the same
# statements with its own implementation. An int-vs-float or key-order difference
# between two of our own components has already cost us once, so pin the bytes.


def test_canonical_statement_bytes_are_pinned():
    assert attestations.evidence_message(
        "sbom", "https://vendor.example/sbom.json", "AB" * 32
    ) == (
        b'{"kind":"sbom","sha256":"' + b"ab" * 32 + b'",'
        b'"statement":"aimarket.evidence.v1",'
        b'"url":"https://vendor.example/sbom.json"}'
    )
    assert attestations.permissions_message(
        product_id="invoice-reader",
        publisher_id="trusted-vendor",
        permissions={"spend_money": False, "execute_code": True},
    ) == (
        b'{"permissions":{"execute_code":true,"spend_money":false},'
        b'"product_id":"invoice-reader","publisher_id":"trusted-vendor",'
        b'"statement":"aimarket.permissions.v1"}'
    )
    assert attestations.violation_message(
        capability_id="invoice.read@v1",
        permission="spend_money",
        permissions_sha256="CD" * 32,
        product_id="invoice-reader",
    ) == (
        b'{"capability_id":"invoice.read@v1","permission":"spend_money",'
        b'"permissions_sha256":"' + b"cd" * 32 + b'",'
        b'"product_id":"invoice-reader","statement":"aimarket.violation.v1"}'
    )


def test_declaration_digest_is_pinned():
    assert attestations.permissions_digest({"spend_money": False}) == (
        __import__("hashlib").sha256(b'{"spend_money":false}').hexdigest()
    )


def test_the_bundled_attested_example_still_verifies():
    """It ships real signatures; an edit that breaks them must fail the build."""
    import json
    from pathlib import Path

    envelope = json.loads(
        (Path(__file__).resolve().parents[1] / "examples" / "attested_candidate.json")
        .read_text(encoding="utf-8")
    )
    report = audit(AuditInput.model_validate(envelope["input"]))
    proof = report["attestations"]
    assert (report["decision"], report["score"], report["findings"]) == ("approve", 100, [])
    assert proof["evidence_verified"] == proof["evidence_declared"] == 2
    assert proof["evidence_independently_attested"] is True
    assert proof["permissions_signature_valid"] is True
    assert proof["permissions_bound_to_provider_key"] is True
    policy = envelope["input"]["policy"]
    for knob in (
        "require_evidence_attestation",
        "require_independent_attestation",
        "require_permission_attestation",
    ):
        assert policy[knob] is True, f"{knob} must stay on: the example proves strict mode is satisfiable"
