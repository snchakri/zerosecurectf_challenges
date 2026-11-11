from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response

from ..config import SESSION_COOKIE_NAME, SESSION_COOKIE_SECURE
from ..db import get_conn
from ..state_machine import get_or_create_session, get_progress

router = APIRouter(prefix="/api", tags=["session"])


def _resolve_session_id(request: Request, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    return request.cookies.get(SESSION_COOKIE_NAME)


@router.get("/session/bootstrap")
def bootstrap(request: Request, response: Response, session_id: str | None = None) -> dict:
    conn = get_conn()
    try:
        requested = _resolve_session_id(request, session_id)
        session, created = get_or_create_session(conn, requested)

        # Always re-set session cookie to keep the browser bound to server state.
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session["session_id"],
            httponly=True,
            secure=SESSION_COOKIE_SECURE,
            samesite="strict",
            path="/",
        )

        return {
            "session_id": session["session_id"],
            "current_layer": int(session["current_layer"]),
            "created": created,
        }
    finally:
        conn.close()


@router.get("/progress")
def progress(request: Request, session_id: str | None = None) -> dict:
    resolved = _resolve_session_id(request, session_id)
    if not resolved:
        raise HTTPException(status_code=401, detail="missing session")

    conn = get_conn()
    try:
        compiled = request.app.state.compiled_data
        payload = get_progress(conn, resolved, compiled)
        if not payload:
            raise HTTPException(status_code=404, detail="session not found")
        return payload
    finally:
        conn.close()
