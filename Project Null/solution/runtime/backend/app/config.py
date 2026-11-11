from __future__ import annotations

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / ".." / "data"
DB_PATH = Path(os.getenv("PROJECT_NULL_DB_PATH", DATA_DIR / "challenge.sqlite")).resolve()
SECRET_KEY = os.getenv("PROJECT_NULL_SECRET_KEY", "dev-only-change-me")
SESSION_COOKIE_NAME = os.getenv("PROJECT_NULL_SESSION_COOKIE", "project_null_session")
SESSION_COOKIE_SECURE = os.getenv("PROJECT_NULL_SESSION_COOKIE_SECURE", "false").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.getenv("PROJECT_NULL_RATE_LIMIT_PER_MINUTE", "40"))
