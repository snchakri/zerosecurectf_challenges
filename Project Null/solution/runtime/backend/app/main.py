from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .data_loader import load_compiled_data
from .db import init_db
from .routes import finalize_router, layer_router, session_router
from .security import SessionRateLimiter

app = FastAPI(title="Project Null Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()
    app.state.compiled_data = load_compiled_data()
    app.state.rate_limiter = SessionRateLimiter()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


app.include_router(session_router)
app.include_router(layer_router)
app.include_router(finalize_router)
