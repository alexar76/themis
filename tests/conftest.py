from __future__ import annotations

import base64
import os
import tempfile
from copy import deepcopy
from pathlib import Path

import pytest

from models import AuditInput

# Importing the FastAPI application creates its persistent provider identity.
# Keep test-only key material out of the repository even when tests are run
# before a mirror secret scan. TemporaryDirectory removes it at interpreter exit.
_TEST_IDENTITY_DIRECTORY = tempfile.TemporaryDirectory(prefix="agent-auditor-tests-")
os.environ["AIMARKET_PROVIDER_IDENTITY_FILE"] = str(
    Path(_TEST_IDENTITY_DIRECTORY.name) / "provider.key"
)


@pytest.fixture
def safe_payload() -> dict:
    return {
        "candidate": {
            "product_id": "invoice-reader",
            "capability_id": "invoice.read@v1",
            "name": "Invoice Reader",
            "description": "Extracts structured invoice fields",
            "invoke_url": "https://agents.example.com/invoke",
            "publisher_id": "trusted-vendor",
            "provider_pubkey": base64.b64encode(b"p" * 32).decode(),
            "price_per_call_usd": 0.02,
            "input_schema": {
                "type": "object",
                "properties": {"document_id": {"type": "string"}},
                "required": ["document_id"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {"total": {"type": "number"}},
                "required": ["total"],
                "additionalProperties": False,
            },
            "verification": {"metis": True},
        },
        "permissions": {
            "read_personal_data": True,
            "human_approval_for_high_impact": True,
        },
        "evidence": [
            {
                "kind": "privacy_policy",
                "url": "https://agents.example.com/privacy",
                "sha256": "a" * 64,
            },
            {
                "kind": "independent_audit",
                "url": "https://audit.example.com/report.pdf",
                "sha256": "b" * 64,
            },
        ],
        "usage": {"monthly_invocations": 1_000, "data_classification": "confidential"},
        "policy": {
            "max_price_per_call_usd": 0.05,
            "max_monthly_cost_usd": 100,
            "minimum_score": 80,
            "minimum_evidence_count": 2,
            "require_https": True,
            "require_provider_key": True,
            "require_metis_declaration": True,
            "approved_publishers": ["trusted-vendor"],
        },
        "request_metis": False,
    }


@pytest.fixture
def safe_input(safe_payload: dict) -> AuditInput:
    return AuditInput.model_validate(deepcopy(safe_payload))
