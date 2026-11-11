from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..config import SESSION_COOKIE_NAME
from ..db import get_conn
from ..state_machine import finalize_session

router = APIRouter(prefix="/api", tags=["finalize"])


class FinalizeRequest(BaseModel):
    final_flag: str = Field(min_length=5)
    session_id: str | None = None


def _resolve_session_id(request: Request, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    return request.cookies.get(SESSION_COOKIE_NAME)


@router.post("/finalize")
def finalize(request: Request, body: FinalizeRequest) -> dict:
    resolved = _resolve_session_id(request, body.session_id)
    if not resolved:
        raise HTTPException(status_code=401, detail="missing session")

    conn = get_conn()
    try:
        try:
            return finalize_session(conn, request.app.state.compiled_data, resolved, body.final_flag)
        except ValueError as exc:
            message = str(exc)
            if message == "session_not_found":
                raise HTTPException(status_code=404, detail=message) from exc
            if message == "not_final_ready":
                raise HTTPException(status_code=403, detail=message) from exc
            raise HTTPException(status_code=400, detail=message) from exc
    finally:
        conn.close()
