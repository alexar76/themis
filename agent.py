from __future__ import annotations

import hmac
import json
import mimetypes
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from auditor import audit, metis_prompt
from federation import load_capability, manifest, well_known
from metis_advisor import VerificationQueue
from models import InvokeEnvelope
from provider_signing import ProviderSigner

PRODUCT_ID = "themis"
CAPABILITY_ID = "agent.security.supply-chain.audit@v1"
MAX_INVOKE_BYTES = 262_144
SIGNER = ProviderSigner()
CAPABILITY = load_capability()
#: The public host this node is reachable on. The Hub keeps calling 127.0.0.1:8080 for
#: admission; this URL is only what the catalogue advertises.
PUBLIC_URL = os.getenv("THEMIS_PUBLIC_URL", "https://themis.modelmarket.dev").rstrip("/")
#: Advertised in the catalogue row. Kept in one place so it cannot drift from pyproject.
VERSION = os.getenv("THEMIS_VERSION", "0.1.0")
METIS_QUEUE = VerificationQueue.from_env()
ROOT = Path(__file__).resolve().parent
UI_DIR = ROOT / "ui"
#: Only ever used as a path oracle_core is told NOT to write (see themis.federation); it
#: still points inside our own tree rather than at oracle_core's default.
DATA_DIR = Path(os.getenv("THEMIS_DATA_DIR", str(ROOT / "data")))
EXAMPLES_DIR = ROOT / "examples"


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


@app.get("/")
def root() -> RedirectResponse:
    """Operator console — live admission receipt UI."""
    return RedirectResponse(url="/ui/", status_code=307)


@app.get("/examples/{name}")
def example_dossier(name: str):
    """Serve bundled candidate envelopes for the admission console."""
    if name not in {"safe_candidate.json", "unsafe_candidate.json", "attested_candidate.json"}:
        return JSONResponse({"detail": "unknown example"}, status_code=404)
    path = EXAMPLES_DIR / name
    if not path.is_file():
        return JSONResponse({"detail": "example missing"}, status_code=404)
    return FileResponse(path, media_type="application/json")


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
        # An operator behind a load balancer needs to see this: a per-process
        # store cannot answer a poll routed to another replica.
        "metis_job_store": METIS_QUEUE.store.kind,
        "metis_job_store_shared": METIS_QUEUE.store.shared,
    }


@app.get("/.well-known/ai-market.json")
def ai_market_well_known() -> JSONResponse:
    """Federation entry point. Without it the hub crawler cannot discover this node, and a
    node outside the federated catalogue is invisible to signal-hunt (which derives its
    sources from it) and to the LOGOS assistant (which answers from the same live list)."""
    return JSONResponse(
        well_known(
            public_url=PUBLIC_URL,
            version=VERSION,
            seed=SIGNER.seed,
            capability=CAPABILITY,
            key_path=DATA_DIR / "manifest_key_unused",
        )
    )


@app.get("/ai-market/v2/manifest")
def ai_market_manifest() -> JSONResponse:
    """Signed catalogue row, signed with the SAME identity as an audit report. The canonical
    form comes from aimarket-oracle-core rather than a local copy — see themis.federation."""
    return JSONResponse(
        manifest(
            public_url=PUBLIC_URL,
            version=VERSION,
            seed=SIGNER.seed,
            capability=CAPABILITY,
            key_path=DATA_DIR / "manifest_key_unused",
        )
    )


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


# The console's webfonts ship in ui/fonts and are declared with a relative href, so they resolve
# under the /ui mount below and need no route of their own. They do need a MIME type: the slim
# base image carries no /etc/mime.types, so `mimetypes` types woff2 as application/octet-stream.
mimetypes.add_type("font/woff2", ".woff2")

# Mount before __main__ so `python agent.py` serves the console (not only TestClient imports).
if UI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")


if __name__ == "__main__":  # pragma: no cover - exercised by container smoke test
    import uvicorn

    uvicorn.run(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8080")))
