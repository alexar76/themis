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


class DeclaredPermissions(StrictModel):
    execute_code: bool = False
    access_secrets: bool = False
    spend_money: bool = False
    write_external_systems: bool = False
    unrestricted_network: bool = False
    read_personal_data: bool = False
    human_approval_for_high_impact: bool = False


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


class AuditInput(StrictModel):
    candidate: CandidateManifest
    permissions: DeclaredPermissions = Field(default_factory=DeclaredPermissions)
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=20)
    usage: UsagePlan = Field(default_factory=UsagePlan)
    policy: ProcurementPolicy = Field(default_factory=ProcurementPolicy)
    request_metis: bool = False


class InvokeEnvelope(StrictModel):
    input: AuditInput
    product_id: str = Field(default="themis", max_length=128)
    capability_id: str = Field(default="agent.security.supply-chain.audit@v1", max_length=192)
