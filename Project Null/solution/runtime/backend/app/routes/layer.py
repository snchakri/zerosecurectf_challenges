from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..config import SESSION_COOKIE_NAME
from ..db import get_conn
from ..security import verify_activation_token
from ..state_machine import activate_layer, get_layer_payload, get_session, submit_layer

router = APIRouter(prefix="/api", tags=["layer"])


class ActivateRequest(BaseModel):
    session_id: str | None = None


class SubmitLayerRequest(BaseModel):
    layer: int = Field(ge=1, le=30)
    key: str = Field(min_length=1)
    activation_token: str = Field(min_length=10)
    session_id: str | None = None


def _resolve_session_id(request: Request, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    return request.cookies.get(SESSION_COOKIE_NAME)


def _check_rate_limit(request: Request, session_id: str) -> None:
    limiter = request.app.state.rate_limiter
    if not limiter.allow(session_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")


@router.get("/layer/{layer}")
def get_layer(request: Request, layer: int, session_id: str | None = None) -> dict[str, Any]:
    if layer < 1 or layer > 30:
        raise HTTPException(status_code=404, detail="layer not found")

    resolved = _resolve_session_id(request, session_id)
    if not resolved:
        raise HTTPException(status_code=401, detail="missing session")

    conn = get_conn()
    try:
        session = get_session(conn, resolved)
        if not session:
            raise HTTPException(status_code=404, detail="session not found")

        current_layer = int(session["current_layer"])
        if layer > current_layer:
            raise HTTPException(status_code=403, detail=f"layer locked; current layer is {current_layer}")

        payload = get_layer_payload(request.app.state.compiled_data, layer)
        if not payload:
            raise HTTPException(status_code=404, detail="layer not found")
        payload["unlocked"] = True
        return payload
    finally:
        conn.close()


@router.post("/layer/{layer}/activate")
def activate(request: Request, layer: int, body: ActivateRequest | None = None) -> dict[str, Any]:
    if layer < 1 or layer > 30:
        raise HTTPException(status_code=404, detail="layer not found")

    resolved = _resolve_session_id(request, body.session_id if body else None)
    if not resolved:
        raise HTTPException(status_code=401, detail="missing session")

    _check_rate_limit(request, resolved)

    conn = get_conn()
    try:
        try:
            payload = activate_layer(conn, request.app.state.compiled_data, resolved, layer)
        except ValueError as exc:
            message = str(exc)
            if message == "session_not_found":
                raise HTTPException(status_code=404, detail=message) from exc
            if message == "session_completed":
                raise HTTPException(status_code=403, detail=message) from exc
            if message == "layer_not_current":
                raise HTTPException(status_code=400, detail=message) from exc
            raise HTTPException(status_code=400, detail=message) from exc
        return payload
    finally:
        conn.close()


@router.post("/submit-layer")
def submit(request: Request, body: SubmitLayerRequest) -> dict[str, Any]:
    resolved = _resolve_session_id(request, body.session_id)
    if not resolved:
        raise HTTPException(status_code=401, detail="missing session")

    _check_rate_limit(request, resolved)

    token_payload = verify_activation_token(body.activation_token)
    if not token_payload:
        raise HTTPException(status_code=401, detail="invalid or expired activation token")

    conn = get_conn()
    try:
        try:
            result = submit_layer(
                conn,
                compiled=request.app.state.compiled_data,
                session_id=resolved,
                layer=body.layer,
                key_submitted=body.key,
                token_payload=token_payload,
            )
        except ValueError as exc:
            message = str(exc)
            if message in {"session_not_found", "layer_not_found"}:
                raise HTTPException(status_code=404, detail=message) from exc
            if message in {"session_completed", "layer_not_current"}:
                raise HTTPException(status_code=403, detail=message) from exc
            if message in {"token_mismatch", "token_invalid"}:
                raise HTTPException(status_code=401, detail=message) from exc
            raise HTTPException(status_code=400, detail=message) from exc

        if result["status"] == "cooldown":
            raise HTTPException(status_code=429, detail=result)

        return result
    finally:
        conn.close()
