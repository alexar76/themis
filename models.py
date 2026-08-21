from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SafeId = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
]
CapabilityId = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*@[vV][0-9]+$"),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
Base64Key = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]{43}=$")]
Base64Signature = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]{86}==$")]
PublisherId = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class VerificationDeclaration(StrictModel):
    metis: bool = False


class CandidateManifest(StrictModel):
    product_id: SafeId
    capability_id: CapabilityId
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2_000)
    invoke_url: str = Field(min_length=1, max_length=2_048)
    publisher_id: PublisherId
    provider_pubkey: str = Field(default="", max_length=128)
    price_per_call_usd: float = Field(ge=0, le=1_000)
    input_schema: dict
    output_schema: dict
    verification: VerificationDeclaration = Field(default_factory=VerificationDeclaration)


PermissionName = Literal[
    "execute_code",
    "access_secrets",
    "spend_money",
    "write_external_systems",
    "unrestricted_network",
    "read_personal_data",
]


class DeclaredPermissions(StrictModel):
    execute_code: bool = False
    access_secrets: bool = False
    spend_money: bool = False
    write_external_systems: bool = False
    unrestricted_network: bool = False
    read_personal_data: bool = False
    human_approval_for_high_impact: bool = False


class Attestation(StrictModel):
    """A signature over a canonical statement, checkable without any network."""

    issuer: Base64Key
    signature: Base64Signature


class EvidenceItem(StrictModel):
    kind: Literal[
        "security_policy",
        "privacy_policy",
        "independent_audit",
        "sbom",
        "incident_response",
        "data_retention",
    ]
    url: str = Field(min_length=1, max_length=2_048)
    sha256: Sha256 | None = None
    # Signed over {kind, sha256, statement, url}. Without it the reference is a
    # claim; with it, some key is on the hook for this exact artifact.
    attestation: Attestation | None = None


class PermissionViolationReport(StrictModel):
    """A signed observation that the capability did what it declared it would not.

    The attestation is mandatory: an unsigned accusation is not evidence, and
    accepting one would hand every competitor a way to reject a rival.
    """

    permission: PermissionName
    attestation: Attestation


class UsagePlan(StrictModel):
    monthly_invocations: int = Field(default=1_000, ge=0, le=10_000_000)
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"


class ProcurementPolicy(StrictModel):
    max_price_per_call_usd: float = Field(default=0.10, ge=0, le=1_000)
    max_monthly_cost_usd: float = Field(default=100.0, ge=0, le=100_000_000)
    minimum_score: int = Field(default=80, ge=0, le=100)
    minimum_evidence_count: int = Field(default=2, ge=0, le=6)
    require_https: bool = True
    require_provider_key: bool = True
    require_metis_declaration: bool = False
    approved_publishers: list[str] = Field(default_factory=list, max_length=100)
    # Undigested references never count toward minimum_evidence_count.
    require_evidence_digests: bool = True
    # Demand a verified signature on every counted evidence item.
    require_evidence_attestation: bool = False
    # Reject a dossier whose only vouchers are the publisher's own key.
    require_independent_attestation: bool = False
    # Demand a signed permission declaration, so a false claim is slashable.
    require_permission_attestation: bool = False
    # When set, only these issuer keys can satisfy an evidence attestation.
    trusted_evidence_issuers: list[Base64Key] = Field(default_factory=list, max_length=32)
    # Distinct observers required before runtime reports reject a declaration. One
    # hostile reporter must never be able to reject a competitor.
    runtime_violation_min_reporters: int = Field(default=2, ge=1, le=16)


class AuditInput(StrictModel):
    candidate: CandidateManifest
    permissions: DeclaredPermissions = Field(default_factory=DeclaredPermissions)
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=20)
    usage: UsagePlan = Field(default_factory=UsagePlan)
    policy: ProcurementPolicy = Field(default_factory=ProcurementPolicy)
    # Signed by the candidate's provider_pubkey over its own declaration.
    permissions_attestation: Attestation | None = None
    # Runtime counter-evidence: observers contradicting the declaration above.
    runtime_violations: list[PermissionViolationReport] = Field(
        default_factory=list, max_length=64
    )
    request_metis: bool = False


class InvokeEnvelope(StrictModel):
    input: AuditInput
    product_id: str = Field(default="themis", max_length=128)
    capability_id: str = Field(default="agent.security.supply-chain.audit@v1", max_length=192)
