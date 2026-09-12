from __future__ import annotations

import json
from copy import deepcopy

import attestations
from attest import main
from auditor import audit
from models import AuditInput


def test_evidence_attestation_from_the_cli_verifies_in_the_auditor(capsys, safe_payload):
    item = safe_payload["evidence"][1]
    assert main(["evidence", "--kind", item["kind"], "--url", item["url"],
                 "--sha256", item["sha256"]]) == 0
    proof = json.loads(capsys.readouterr().out)
    assert attestations.verify(
        issuer=proof["issuer"],
        signature=proof["signature"],
        message=attestations.evidence_message(item["kind"], item["url"], item["sha256"]),
    )
    safe_payload["evidence"][1] = {**item, "attestation": proof}
    report = audit(AuditInput.model_validate(deepcopy(safe_payload)))
    assert report["attestations"]["evidence_verified"] == 1
    assert report["decision"] == "approve"


def test_permission_attestation_from_the_cli_binds_to_the_provider_key(
    capsys, tmp_path, safe_payload
):
    assert main(["evidence", "--kind", "sbom", "--url", "https://x/s.json",
                 "--sha256", "a" * 64]) == 0
    issuer = json.loads(capsys.readouterr().out)["issuer"]
    safe_payload["candidate"]["provider_pubkey"] = issuer
    dossier = tmp_path / "dossier.json"
    dossier.write_text(json.dumps({"input": safe_payload}), encoding="utf-8")

    assert main(["permissions", "--dossier", str(dossier)]) == 0
    proof = json.loads(capsys.readouterr().out)
    safe_payload["permissions_attestation"] = proof
    report = audit(AuditInput.model_validate(deepcopy(safe_payload)))
    assert report["attestations"]["permissions_bound_to_provider_key"] is True
    assert report["decision"] == "approve"


def test_cli_refuses_a_malformed_digest_and_an_unreadable_dossier(capsys, tmp_path):
    assert main(["evidence", "--kind", "sbom", "--url", "https://x", "--sha256", "nope"]) == 2
    assert main(["permissions", "--dossier", str(tmp_path / "missing.json")]) == 2
    broken = tmp_path / "broken.json"
    broken.write_text('{"input": {"candidate": {}}}', encoding="utf-8")
    assert main(["permissions", "--dossier", str(broken)]) == 2
    assert "not a valid audit input" in capsys.readouterr().err
