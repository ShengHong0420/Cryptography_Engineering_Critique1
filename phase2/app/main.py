"""
Phase 2 – FastAPI application entry point.
TOTP 2FA login system.
"""

import hashlib
import io
import base64
from pathlib import Path

import qrcode
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from phase2.app.database import get_db, JSONStore
from phase2.app.models import User
from phase2.app.totp import generate_secret, get_totp_uri, verify_totp

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Phase 2 – TOTP 2FA")

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# Simple in-memory session store: {session_token: {"username": ..., "verified": bool}}
sessions: dict[str, dict] = {}


@app.on_event("startup")
def startup_event():
    print("=" * 60)
    print("Click here to open: http://localhost:8000")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _prehash_password(password: str) -> str:
    """SHA-256 hex-digest of the password to stay within bcrypt's 72-byte limit."""
    return hashlib.sha256(password.encode()).hexdigest()


def _make_session_token() -> str:
    import os, binascii
    return binascii.hexlify(os.urandom(24)).decode()


def _get_session(request: Request) -> dict | None:
    token = request.cookies.get("session_token")
    if token and token in sessions:
        return sessions[token]
    return None


def _require_verified_session(request: Request):
    sess = _get_session(request)
    if not sess or not sess.get("verified"):
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return sess


def _qrcode_base64(uri: str) -> str:
    """Generate a QR code PNG from a URI and return as base64 string."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=RedirectResponse)
def root():
    return RedirectResponse(url="/login", status_code=302)


# ── Registration ──────────────────────────────────────────────────────────

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: JSONStore = Depends(get_db),
):
    # Check for duplicate username
    existing = db.get_user_by_username(username)
    if existing:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username already taken. Please choose another."},
        )

    secret = generate_secret()
    hashed = pwd_context.hash(_prehash_password(password))
    user = db.add_user(username, hashed, secret)

    # Build QR code for Google Authenticator
    uri = get_totp_uri(secret, username)
    qr_b64 = _qrcode_base64(uri)

    return templates.TemplateResponse(
        "register_success.html",
        {
            "request": request,
            "username": username,
            "secret": secret,
            "qr_b64": qr_b64,
        },
    )


# ── Login (step 1: password) ───────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: JSONStore = Depends(get_db),
):
    user = db.get_user_by_username(username)
    if not user or not pwd_context.verify(_prehash_password(password), user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password."},
        )

    # Password OK → create a pending (unverified) session, then ask for TOTP
    token = _make_session_token()
    sessions[token] = {"username": username, "verified": False}

    response = RedirectResponse(url="/verify", status_code=302)
    response.set_cookie("session_token", token, httponly=True, samesite="lax")
    return response


# ── TOTP verification (step 2) ─────────────────────────────────────────────

@app.get("/verify", response_class=HTMLResponse)
def verify_form(request: Request):
    sess = _get_session(request)
    if not sess:
        return RedirectResponse(url="/login", status_code=302)
    if sess.get("verified"):
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("verify.html", {"request": request, "error": None})


@app.post("/verify", response_class=HTMLResponse)
def verify(
    request: Request,
    code: str = Form(...),
    db: JSONStore = Depends(get_db),
):
    sess = _get_session(request)
    if not sess:
        return RedirectResponse(url="/login", status_code=302)

    username = sess["username"]
    user = db.get_user_by_username(username)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    if not verify_totp(user.totp_secret, code.strip()):
        return templates.TemplateResponse(
            "verify.html",
            {"request": request, "error": "Invalid or expired code. Please try again."},
        )

    # Mark session as fully verified
    sess["verified"] = True
    return RedirectResponse(url="/dashboard", status_code=302)


# ── Dashboard (protected) ─────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: JSONStore = Depends(get_db)):
    sess = _get_session(request)
    if not sess or not sess.get("verified"):
        return RedirectResponse(url="/login", status_code=302)

    username = sess["username"]
    user = db.get_user_by_username(username)

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "username": username, "user": user},
    )


# ── Logout ────────────────────────────────────────────────────────────────

@app.get("/logout")
def logout(request: Request):
    token = request.cookies.get("session_token")
    if token and token in sessions:
        del sessions[token]
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_token")
    return response
