from __future__ import annotations

import hmac
import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from auditor import audit, metis_prompt
from metis_advisor import VerificationQueue
from models import InvokeEnvelope
from provider_signing import ProviderSigner

PRODUCT_ID = "themis"
CAPABILITY_ID = "agent.security.supply-chain.audit@v1"
MAX_INVOKE_BYTES = 262_144
SIGNER = ProviderSigner()
METIS_QUEUE = VerificationQueue.from_env()


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await METIS_QUEUE.close()


app = FastAPI(
    title="THEMIS",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.middleware("http")
async def request_boundary(request: Request, call_next):
    response = None
    if request.method == "POST" and request.url.path == "/invoke":
        raw_length = request.headers.get("content-length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0 or length > MAX_INVOKE_BYTES:
            response = JSONResponse(
                {"detail": f"request body must be 0-{MAX_INVOKE_BYTES} bytes"},
                status_code=413,
            )
    if response is None:
        response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "agent": PRODUCT_ID,
        "kind": "tool",
        "provider_pubkey": SIGNER.public_key_b64,
        "metis_configured": METIS_QUEUE.advisor.enabled,
    }


@app.post("/invoke")
async def invoke(raw_request: Request, request: InvokeEnvelope) -> JSONResponse:
    if not hmac.compare_digest(request.product_id, PRODUCT_ID):
        return JSONResponse({"detail": "product_id does not match this provider"}, status_code=400)
    if not hmac.compare_digest(request.capability_id, CAPABILITY_ID):
        return JSONResponse({"detail": "capability_id does not match this provider"}, status_code=400)

    # Bind the signature to the exact submitted input, not to Pydantic's
    # default-expanded representation. Reject duplicate JSON keys so two
    # parsers cannot disagree about what was signed.
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        raw_envelope = json.loads(await raw_request.body(), object_pairs_hook=unique_object)
        input_payload = raw_envelope["input"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return JSONResponse({"detail": "request must contain unambiguous JSON"}, status_code=400)

    report = audit(request.input)
    if request.input.request_metis:
        metis = await METIS_QUEUE.submit(metis_prompt(report))
    else:
        metis = {"status": "skipped", "reason": "not_requested"}
    result = {**report, "metis": metis}
    return JSONResponse(
        {"success": True, "result": result},
        headers={
            "X-Provider-Signature": SIGNER.sign_result(
                result,
                capability_id=CAPABILITY_ID,
                product_id=PRODUCT_ID,
                input_payload=input_payload,
            )
        },
    )


@app.get("/verification/{verification_id}")
async def verification(verification_id: str) -> JSONResponse:
    if not 8 <= len(verification_id) <= 64 or not all(
        char.isalnum() or char in "-_" for char in verification_id
    ):
        return JSONResponse({"detail": "verification not found"}, status_code=404)
    state = await METIS_QUEUE.get(verification_id)
    if state is None:
        return JSONResponse({"detail": "verification not found"}, status_code=404)
    result = {"metis": state}
    return JSONResponse(
        {"success": True, "result": result},
        headers={
            "X-Provider-Signature": SIGNER.sign_result(
                result,
                capability_id=CAPABILITY_ID,
                product_id=PRODUCT_ID,
                input_payload={"verification_id": verification_id},
            )
        },
    )


if __name__ == "__main__":  # pragma: no cover - exercised by container smoke test
    import uvicorn

    uvicorn.run(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8080")))
