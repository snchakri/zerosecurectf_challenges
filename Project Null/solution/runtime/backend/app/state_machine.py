from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .data_loader import CompiledData
from .db import utcnow
from .security import issue_activation_token, new_nonce


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def get_or_create_session(conn: sqlite3.Connection, requested_session_id: str | None = None) -> tuple[dict[str, Any], bool]:
    if requested_session_id:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (requested_session_id,),
        ).fetchone()
        if row:
            return _row_to_dict(row), False

    session_id = str(uuid.uuid4())
    now = utcnow()
    conn.execute(
        """
        INSERT INTO sessions (session_id, current_layer, final_ready, completed, false_positive_count, cooldown_until, created_at, updated_at)
        VALUES (?, 1, 0, 0, 0, NULL, ?, ?)
        """,
        (session_id, now, now),
    )
    conn.commit()
    created = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    return _row_to_dict(created), True


def get_session(conn: sqlite3.Connection, session_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    return _row_to_dict(row)


def _fragments_for_session(conn: sqlite3.Connection, session_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    verified_rows = conn.execute(
        """
        SELECT layer, fragment_id, awarded_at
        FROM fragments
        WHERE session_id = ? AND kind = 'verified'
        ORDER BY layer
        """,
        (session_id,),
    ).fetchall()
    poison_rows = conn.execute(
        """
        SELECT layer, fragment_id, awarded_at
        FROM fragments
        WHERE session_id = ? AND kind = 'poison'
        ORDER BY layer
        """,
        (session_id,),
    ).fetchall()
    verified = [dict(row) for row in verified_rows]
    poison = [dict(row) for row in poison_rows]
    return verified, poison


def recompute_final_ready(conn: sqlite3.Connection, session_id: str, compiled: CompiledData) -> bool:
    verified, poison = _fragments_for_session(conn, session_id)
    ready = len(verified) >= compiled.requires_all_verified_layers
    if compiled.reject_if_any_poison_fragment and poison:
        ready = False

    conn.execute(
        "UPDATE sessions SET final_ready = ?, updated_at = ? WHERE session_id = ?",
        (1 if ready else 0, utcnow(), session_id),
    )
    conn.commit()
    return ready


def get_progress(conn: sqlite3.Connection, session_id: str, compiled: CompiledData) -> dict[str, Any] | None:
    session = get_session(conn, session_id)
    if not session:
        return None

    ready = recompute_final_ready(conn, session_id, compiled)
    session["final_ready"] = 1 if ready else 0

    verified, poison = _fragments_for_session(conn, session_id)
    current_layer = int(session["current_layer"])

    activation_row = conn.execute(
        """
        SELECT layer, expires_at, used
        FROM activations
        WHERE session_id = ? AND layer = ?
        """,
        (session_id, current_layer),
    ).fetchone()

    activation = None
    if activation_row:
        expires_at = _parse_iso(activation_row["expires_at"])
        activation = {
            "layer": activation_row["layer"],
            "active": bool(activation_row["used"] == 0 and expires_at and expires_at > _now()),
            "expires_at": activation_row["expires_at"],
        }

    return {
        "session_id": session_id,
        "current_layer": current_layer,
        "completed": bool(session["completed"]),
        "final_ready": bool(session["final_ready"]),
        "verified_fragments": verified,
        "poison_fragments": poison,
        "cooldown_until": session["cooldown_until"],
        "activation": activation,
    }


def get_layer_payload(compiled: CompiledData, layer: int) -> dict[str, Any] | None:
    layer_def = compiled.layers.get(layer)
    if not layer_def:
        return None
    return {
        "layer": layer_def.layer,
        "id": layer_def.id,
        "title": layer_def.title,
        "act": layer_def.act,
        "timer_seconds": layer_def.timer_seconds,
        "public_asset": layer_def.public_asset,
    }


def activate_layer(conn: sqlite3.Connection, compiled: CompiledData, session_id: str, layer: int) -> dict[str, Any]:
    session = get_session(conn, session_id)
    if not session:
        raise ValueError("session_not_found")
    if session["completed"]:
        raise ValueError("session_completed")
    if int(session["current_layer"]) != layer:
        raise ValueError("layer_not_current")

    layer_def = compiled.layers.get(layer)
    if not layer_def:
        raise ValueError("layer_not_found")

    nonce = new_nonce()
    expires_at = _now() + timedelta(seconds=layer_def.timer_seconds)
    expires_at_iso = expires_at.isoformat()

    conn.execute(
        """
        INSERT INTO activations (session_id, layer, nonce, expires_at, used, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
        ON CONFLICT(session_id, layer) DO UPDATE SET
          nonce = excluded.nonce,
          expires_at = excluded.expires_at,
          used = 0,
          created_at = excluded.created_at
        """,
        (session_id, layer, nonce, expires_at_iso, utcnow()),
    )
    conn.commit()

    token = issue_activation_token(session_id, layer, nonce, int(expires_at.timestamp()))
    return {
        "activation_token": token,
        "expires_in_seconds": layer_def.timer_seconds,
        "expires_at": expires_at_iso,
    }


def _activation_valid_and_mark_used(
    conn: sqlite3.Connection,
    *,
    session_id: str,
    layer: int,
    nonce: str,
) -> bool:
    row = conn.execute(
        "SELECT nonce, expires_at, used FROM activations WHERE session_id = ? AND layer = ?",
        (session_id, layer),
    ).fetchone()
    if not row:
        return False
    if row["used"]:
        return False
    if row["nonce"] != nonce:
        return False
    expires_at = _parse_iso(row["expires_at"])
    if not expires_at or expires_at <= _now():
        return False

    conn.execute(
        "UPDATE activations SET used = 1 WHERE session_id = ? AND layer = ?",
        (session_id, layer),
    )
    conn.commit()
    return True


def submit_layer(
    conn: sqlite3.Connection,
    *,
    compiled: CompiledData,
    session_id: str,
    layer: int,
    key_submitted: str,
    token_payload: dict[str, Any],
) -> dict[str, Any]:
    session = get_session(conn, session_id)
    if not session:
        raise ValueError("session_not_found")
    if session["completed"]:
        raise ValueError("session_completed")
    if int(session["current_layer"]) != layer:
        raise ValueError("layer_not_current")

    cooldown_until = _parse_iso(session["cooldown_until"])
    now = _now()
    if cooldown_until and cooldown_until > now:
        remaining = int((cooldown_until - now).total_seconds())
        return {
            "status": "cooldown",
            "retry_after_seconds": max(1, remaining),
        }

    if token_payload.get("session_id") != session_id or int(token_payload.get("layer", -1)) != layer:
        raise ValueError("token_mismatch")

    nonce = str(token_payload.get("nonce", ""))
    if not _activation_valid_and_mark_used(conn, session_id=session_id, layer=layer, nonce=nonce):
        raise ValueError("token_invalid")

    layer_def = compiled.layers.get(layer)
    if not layer_def:
        raise ValueError("layer_not_found")

    normalized = key_submitted.strip().lower()
    status = "incorrect"
    fragment_id: str | None = None

    if normalized in layer_def.canonical_aliases:
        status = "correct"
        fragment_id = layer_def.verified_fragment
        conn.execute(
            """
            INSERT OR IGNORE INTO fragments (session_id, layer, fragment_id, kind, awarded_at)
            VALUES (?, ?, ?, 'verified', ?)
            """,
            (session_id, layer, fragment_id, utcnow()),
        )

        next_layer = min(layer + 1, max(compiled.layers))
        conn.execute(
            "UPDATE sessions SET current_layer = ?, updated_at = ? WHERE session_id = ?",
            (next_layer, utcnow(), session_id),
        )

    elif normalized in layer_def.false_positive_aliases:
        status = "false_positive"
        fragment_id = layer_def.poison_fragment
        conn.execute(
            """
            INSERT OR IGNORE INTO fragments (session_id, layer, fragment_id, kind, awarded_at)
            VALUES (?, ?, ?, 'poison', ?)
            """,
            (session_id, layer, fragment_id, utcnow()),
        )

        fp_count = int(session["false_positive_count"]) + 1
        penalty_seconds = min(300, 30 * (2 ** (fp_count - 1)))
        cooldown_until_iso = (_now() + timedelta(seconds=penalty_seconds)).isoformat()
        conn.execute(
            """
            UPDATE sessions
            SET false_positive_count = ?, cooldown_until = ?, updated_at = ?
            WHERE session_id = ?
            """,
            (fp_count, cooldown_until_iso, utcnow(), session_id),
        )

    conn.execute(
        """
        INSERT INTO submissions (session_id, layer, key_submitted, status, submitted_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (session_id, layer, key_submitted, status, utcnow()),
    )
    conn.commit()

    ready = recompute_final_ready(conn, session_id, compiled)
    fresh_session = get_session(conn, session_id)
    response = {
        "status": status,
        "fragment": fragment_id,
        "current_layer": int(fresh_session["current_layer"]),
        "final_ready": ready,
    }

    if status == "false_positive":
        cooldown_until = _parse_iso(fresh_session["cooldown_until"])
        if cooldown_until:
            response["cooldown_until"] = cooldown_until.isoformat()

    return response


def finalize_session(conn: sqlite3.Connection, compiled: CompiledData, session_id: str, final_flag: str) -> dict[str, Any]:
    session = get_session(conn, session_id)
    if not session:
        raise ValueError("session_not_found")
    if session["completed"]:
        return {"status": "completed", "message": "session already completed"}

    ready = recompute_final_ready(conn, session_id, compiled)
    if not ready:
        raise ValueError("not_final_ready")

    if final_flag.strip() != compiled.final_flag:
        return {"status": "rejected", "message": "incorrect final flag"}

    conn.execute(
        "UPDATE sessions SET completed = 1, updated_at = ? WHERE session_id = ?",
        (utcnow(), session_id),
    )
    conn.commit()
    return {"status": "completed", "message": "final flag accepted"}
