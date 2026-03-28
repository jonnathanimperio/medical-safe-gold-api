"""Medical Safe Gold - Secure Backend API"""

import os
import csv
import io
import asyncio
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

# --- Configuration ---
MONGO_URI = os.environ.get("MONGO_URI", "")
MASTER_KEY = os.environ.get("MASTER_KEY", "")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is required. Set it before starting the server.")
if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY environment variable is required. Set it before starting the server.")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_urlsafe(64))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24
TRIAL_DAYS = 7
DB_NAME = "medical_safe_gold"

ADMIN_KEY = os.environ.get("ADMIN_KEY", "msggold-admin-2024-secret")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@medicalsafegold.com")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")

# --- App ---
app = FastAPI(title="Medical Safe Gold API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Database ---
client: Optional[AsyncIOMotorClient] = None
db = None


@app.on_event("startup")
async def startup_db():
    global client, db
    client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    await db.users.create_index("email", unique=True)
    await db.agendamentos.create_index("clinica_id")
    await db.licenses.create_index("key", unique=True)
    await db.licenses.create_index("email")
    await db.password_resets.create_index("token", unique=True)
    await db.password_resets.create_index("expires_at", expireAfterSeconds=0)


@app.on_event("shutdown")
async def shutdown_db():
    global client
    if client:
        client.close()


# --- Models ---
class RegisterRequest(BaseModel):
    email: str
    password: str
    machine_id: str
    license_key: str


class LoginRequest(BaseModel):
    email: str
    password: str
    machine_id: str


class AppointmentSave(BaseModel):
    payload: str  # Already encrypted by the client
    clinica_id: str


class AppointmentDelete(BaseModel):
    id: str
    clinica_id: str


class SubscriptionActivate(BaseModel):
    email: str
    plan: str  # "monthly" or "annual"
    transaction_id: str


class AuthResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    fernet_key: Optional[str] = None
    clinica_id: Optional[str] = None
    subscription_status: Optional[str] = None
    subscription_plan: Optional[str] = None
    subscription_expires: Optional[str] = None
    error: Optional[str] = None


class LicenseGenerateRequest(BaseModel):
    email: str
    plan: str = "monthly"
    send_email: bool = True


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


# --- Helpers ---
def generate_user_fernet_key() -> str:
    """Generate a unique Fernet key for a new user."""
    return Fernet.generate_key().decode()


def encrypt_user_key(user_key: str) -> str:
    """Encrypt a user's Fernet key with the master key for storage."""
    f = Fernet(MASTER_KEY.encode() if isinstance(MASTER_KEY, str) else MASTER_KEY)
    return f.encrypt(user_key.encode()).decode()


def decrypt_user_key(encrypted_key: str) -> str:
    """Decrypt a user's Fernet key from storage."""
    f = Fernet(MASTER_KEY.encode() if isinstance(MASTER_KEY, str) else MASTER_KEY)
    return f.decrypt(encrypted_key.encode()).decode()


def create_jwt_token(email: str) -> str:
    """Create a JWT token for authenticated sessions."""
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def verify_token(
    authorization: Optional[str] = Header(None),
    x_authorization: Optional[str] = Header(None),
) -> str:
    raw = x_authorization or authorization
    if not raw:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        token = raw.replace("Bearer ", "")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def verify_admin(x_admin_key: str = Header(...)) -> bool:
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    return True


def check_subscription(user: dict) -> tuple[bool, str]:
    status = user.get("subscription_status", "trial")
    expires = user.get("subscription_expires")

    if status == "trial":
        if expires and datetime.now(timezone.utc) > expires.replace(tzinfo=timezone.utc):
            return False, "trial_expired"
        return True, "trial"

    if status == "active":
        if expires and datetime.now(timezone.utc) > expires.replace(tzinfo=timezone.utc):
            return False, "expired"
        return True, "active"

    return False, status


def generate_license_key() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    parts = []
    for _ in range(4):
        part = "".join(secrets.choice(chars) for _ in range(4))
        parts.append(part)
    return "-".join(parts)


def _send_email_via_brevo(to_email, subject, html_body):
    """Send email via Brevo (Sendinblue) HTTP API - 300 emails/day free."""
    import json
    import urllib.request
    data = json.dumps({
        "sender": {"name": "Medical Safe Gold", "email": SMTP_FROM},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_body,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=data,
        headers={
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
        print(f"Brevo API response: {result}")
    return True


def _send_email_via_resend(to_email, subject, html_body):
    """Send email via Resend HTTP API - works on platforms that block SMTP."""
    import json
    import urllib.request
    data = json.dumps({
        "from": SMTP_FROM,
        "to": [to_email],
        "subject": subject,
        "html": html_body,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=data,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
        print(f"Resend API response: {result}")
    return True


def _send_email_via_smtp(to_email, subject, html_body):
    """Send email via SMTP - works when SMTP ports are not blocked."""
    import smtplib
    import ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, 465, timeout=30, context=context) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, to_email, msg.as_string())
        return True
    except Exception as e_ssl:
        print(f"SMTP_SSL (465) failed: {e_ssl}, trying STARTTLS (587)...")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, to_email, msg.as_string())
        return True


def _send_email_sync(to_email, subject, html_body):
    """Send email using best available method. Priority: Brevo > Resend > SMTP."""
    if BREVO_API_KEY:
        return _send_email_via_brevo(to_email, subject, html_body)
    elif RESEND_API_KEY:
        return _send_email_via_resend(to_email, subject, html_body)
    elif SMTP_USER and SMTP_PASSWORD:
        return _send_email_via_smtp(to_email, subject, html_body)
    else:
        raise RuntimeError("No email provider configured")


async def send_license_email(to_email, license_key, plan):
    if not BREVO_API_KEY and not RESEND_API_KEY and (not SMTP_USER or not SMTP_PASSWORD):
        return False
    try:
        plan_name = "Mensal (R$ 69/mes)" if plan == "monthly" else "Anual (R$ 549/ano)"
        html = '<div style="font-family:Arial;max-width:600px;margin:0 auto;background:#0a0a0f;color:#fff;padding:30px;border-radius:12px;">'
        html += '<div style="text-align:center;margin-bottom:30px;"><h1 style="color:#d4af37;">Medical Safe Gold</h1><p style="color:#888;">Sua Chave de Licenca</p></div>'
        html += f'<div style="background:#1a1a2e;border:1px solid #d4af37;border-radius:8px;padding:20px;text-align:center;margin:20px 0;"><p style="color:#888;">Sua chave:</p><h2 style="color:#d4af37;font-family:monospace;letter-spacing:3px;font-size:24px;">{license_key}</h2></div>'
        html += f'<div style="background:#1a1a2e;border-radius:8px;padding:15px;"><p style="color:#ccc;"><strong>Plano:</strong> {plan_name}</p><p style="color:#ccc;"><strong>E-mail:</strong> {to_email}</p></div>'
        html += '<div style="margin-top:20px;padding:15px;background:#1a1a2e;border-radius:8px;"><h3 style="color:#d4af37;">Como usar:</h3><ol style="color:#ccc;"><li>Instale o Medical Safe Gold</li><li>Na tela de cadastro, insira seu e-mail e crie uma senha</li><li>Cole a chave de licenca acima</li><li>Pronto!</li></ol></div>'
        html += '<div style="text-align:center;margin-top:30px;color:#666;font-size:12px;"><p>Suporte: jonnathancoelhosilvacoelho@gmail.com | WhatsApp: +55 (11) 94849-6712</p></div></div>'
        subject = f"Medical Safe Gold - Sua Chave de Licenca: {license_key}"
        return await asyncio.to_thread(_send_email_sync, to_email, subject, html)
    except Exception as e:
        print(f"Email send error: {e}")
        return False


async def send_reset_email(to_email, reset_token):
    if not BREVO_API_KEY and not RESEND_API_KEY and (not SMTP_USER or not SMTP_PASSWORD):
        return False, "No email provider configured (set BREVO_API_KEY, RESEND_API_KEY, or SMTP_USER/SMTP_PASSWORD)"
    try:
        html = '<div style="font-family:Arial;max-width:600px;margin:0 auto;background:#0a0a0f;color:#fff;padding:30px;border-radius:12px;">'
        html += '<div style="text-align:center;margin-bottom:30px;"><h1 style="color:#d4af37;">Medical Safe Gold</h1><p style="color:#888;">Recuperacao de Senha</p></div>'
        html += f'<div style="background:#1a1a2e;border:1px solid #d4af37;border-radius:8px;padding:20px;text-align:center;margin:20px 0;"><p style="color:#888;">Seu codigo de recuperacao:</p><h2 style="color:#d4af37;font-family:monospace;letter-spacing:3px;font-size:28px;">{reset_token}</h2></div>'
        html += '<p style="color:#ccc;text-align:center;">Este codigo expira em 1 hora.</p>'
        html += '<p style="color:#ccc;text-align:center;">Se voce nao solicitou, ignore este e-mail.</p></div>'
        subject = f"Medical Safe Gold - Codigo de Recuperacao: {reset_token}"
        await asyncio.to_thread(_send_email_sync, to_email, subject, html)
        return True, None
    except Exception as e:
        error_msg = str(e)
        print(f"Reset email send error: {error_msg}")
        return False, error_msg


# --- Auth Endpoints ---
@app.post("/auth/register", response_model=AuthResponse)
async def register(req: RegisterRequest):
    """Register with license key validation, binds email + hardware ID to key."""
    if not req.email or not req.password:
        return AuthResponse(success=False, error="MISSING_FIELDS")
    if not req.license_key:
        return AuthResponse(success=False, error="MISSING_LICENSE_KEY")

    email = req.email.strip().lower()
    license_key = req.license_key.strip().upper()

    # Validate license key
    license_doc = await db.licenses.find_one({"key": license_key})
    if not license_doc:
        return AuthResponse(success=False, error="INVALID_LICENSE_KEY")
    if license_doc.get("status") == "activated":
        if license_doc.get("email") != email:
            return AuthResponse(success=False, error="LICENSE_ALREADY_USED")
    if license_doc.get("status") == "revoked":
        return AuthResponse(success=False, error="LICENSE_REVOKED")

    existing = await db.users.find_one({"email": email})
    if existing:
        return AuthResponse(success=False, error="USER_EXISTS")

    password_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt(10))
    user_fernet_key = generate_user_fernet_key()
    encrypted_fernet_key = encrypt_user_key(user_fernet_key)

    plan = license_doc.get("plan", "monthly")
    if plan == "monthly":
        expires = datetime.now(timezone.utc) + timedelta(days=30)
    elif plan == "annual":
        expires = datetime.now(timezone.utc) + timedelta(days=365)
    else:
        expires = datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)

    await db.users.insert_one({
        "email": email,
        "password_hash": password_hash.decode() if isinstance(password_hash, bytes) else password_hash,
        "machine_id": req.machine_id,
        "fernet_key_encrypted": encrypted_fernet_key,
        "license_key": license_key,
        "subscription_status": "active",
        "subscription_plan": plan,
        "subscription_expires": expires,
        "created_at": datetime.now(timezone.utc),
        "last_login": datetime.now(timezone.utc),
    })

    # Bind email + machine_id to license
    await db.licenses.update_one(
        {"key": license_key},
        {"$set": {
            "status": "activated", "email": email,
            "machine_id": req.machine_id, "activated_at": datetime.now(timezone.utc),
        }},
    )

    token = create_jwt_token(email)
    return AuthResponse(
        success=True, token=token, fernet_key=user_fernet_key, clinica_id=email,
        subscription_status="active", subscription_plan=plan, subscription_expires=expires.isoformat(),
    )


@app.post("/auth/login", response_model=AuthResponse)
async def login(req: LoginRequest):
    """Login with email/password, returns JWT + user's Fernet key."""
    email = req.email.strip().lower()

    user = await db.users.find_one({"email": email})
    if not user:
        return AuthResponse(success=False, error="USER_NOT_FOUND")

    # Verify password
    stored_hash = user["password_hash"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode()

    if not bcrypt.checkpw(req.password.encode(), stored_hash):
        return AuthResponse(success=False, error="WRONG_PASSWORD")

    # Check subscription
    is_active, status = check_subscription(user)
    if not is_active:
        return AuthResponse(
            success=False,
            error="SUBSCRIPTION_EXPIRED",
            subscription_status=status,
        )

    # Decrypt user's Fernet key
    try:
        user_fernet_key = decrypt_user_key(user["fernet_key_encrypted"])
    except Exception:
        # Legacy user without per-user key - generate one now
        user_fernet_key = generate_user_fernet_key()
        encrypted_key = encrypt_user_key(user_fernet_key)
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"fernet_key_encrypted": encrypted_key}},
        )

    # Update last login
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.now(timezone.utc), "machine_id": req.machine_id}},
    )

    token = create_jwt_token(email)

    return AuthResponse(
        success=True,
        token=token,
        fernet_key=user_fernet_key,
        clinica_id=email,
        subscription_status=user.get("subscription_status", "trial"),
        subscription_plan=user.get("subscription_plan"),
        subscription_expires=user.get("subscription_expires", "").isoformat()
        if user.get("subscription_expires")
        else None,
    )


# --- Appointment Endpoints ---
@app.post("/appointments")
async def save_appointment(data: AppointmentSave, email: str = Depends(verify_token)):
    """Save an encrypted appointment."""
    result = await db.agendamentos.insert_one({
        "payload": data.payload,
        "clinica_id": data.clinica_id,
    })
    return {"success": True, "id": str(result.inserted_id)}


@app.get("/appointments/{clinica_id}")
async def get_appointments(clinica_id: str, email: str = Depends(verify_token)):
    """Get all encrypted appointments for a clinic."""
    docs = await db.agendamentos.find({"clinica_id": clinica_id}).to_list(length=10000)
    results = []
    for doc in docs:
        results.append({
            "id": str(doc["_id"]),
            "payload": doc["payload"],
        })
    return {"success": True, "data": results}


@app.delete("/appointments/{appointment_id}")
async def delete_appointment(
    appointment_id: str,
    clinica_id: str,
    email: str = Depends(verify_token),
):
    """Delete an appointment by ID."""
    from bson import ObjectId

    await db.agendamentos.delete_one({
        "_id": ObjectId(appointment_id),
        "clinica_id": clinica_id,
    })
    return {"success": True}


# --- Forgot Password ---
@app.post("/auth/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    email = req.email.strip().lower()
    user = await db.users.find_one({"email": email})
    if not user:
        return {"success": True, "message": "If the email exists, a reset code has been sent."}
    reset_code = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    await db.password_resets.delete_many({"email": email})
    await db.password_resets.insert_one({
        "email": email, "token": reset_code,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "created_at": datetime.now(timezone.utc),
    })
    email_sent, email_error = await send_reset_email(email, reset_code)
    return {
        "success": True, "message": "If the email exists, a reset code has been sent.",
        "email_sent": email_sent,
    }


@app.post("/auth/reset-password")
async def reset_password(req: ResetPasswordRequest):
    if not req.token or not req.new_password:
        raise HTTPException(status_code=400, detail="Missing token or password")
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    reset_doc = await db.password_resets.find_one({
        "token": req.token.strip(),
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    if not reset_doc:
        raise HTTPException(status_code=400, detail="INVALID_OR_EXPIRED_CODE")
    email = reset_doc["email"]
    password_hash = bcrypt.hashpw(req.new_password.encode(), bcrypt.gensalt(10))
    result = await db.users.update_one(
        {"email": email},
        {"$set": {"password_hash": password_hash.decode() if isinstance(password_hash, bytes) else password_hash}},
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await db.password_resets.delete_many({"email": email})
    return {"success": True, "message": "Password reset successfully"}


# --- Subscription Endpoints ---
@app.post("/subscription/activate")
async def activate_subscription(data: SubscriptionActivate):
    """Activate a subscription (called by Mercado Pago webhook or admin)."""
    email = data.email.strip().lower()
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if data.plan == "monthly":
        expires = datetime.now(timezone.utc) + timedelta(days=30)
    elif data.plan == "annual":
        expires = datetime.now(timezone.utc) + timedelta(days=365)
    else:
        raise HTTPException(status_code=400, detail="Invalid plan")

    await db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "subscription_status": "active",
                "subscription_plan": data.plan,
                "subscription_expires": expires,
                "last_transaction_id": data.transaction_id,
            }
        },
    )

    return {"success": True, "expires": expires.isoformat()}


@app.get("/subscription/status/{user_email}")
async def subscription_status(user_email: str, email: str = Depends(verify_token)):
    """Check subscription status."""
    target_email = user_email.strip().lower()
    user = await db.users.find_one({"email": target_email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    is_active, status = check_subscription(user)

    return {
        "active": is_active,
        "status": status,
        "plan": user.get("subscription_plan"),
        "expires": user.get("subscription_expires", "").isoformat()
        if user.get("subscription_expires")
        else None,
    }


# --- Admin Endpoints ---
@app.post("/admin/license/generate")
async def admin_generate_license(req: LicenseGenerateRequest, admin: bool = Depends(verify_admin)):
    email = req.email.strip().lower()
    key = generate_license_key()
    await db.licenses.insert_one({
        "key": key, "email": email, "plan": req.plan, "status": "pending",
        "machine_id": None, "created_at": datetime.now(timezone.utc), "activated_at": None,
    })
    email_sent = False
    if req.send_email:
        email_sent = await send_license_email(email, key, req.plan)
    return {"success": True, "license_key": key, "email": email, "plan": req.plan, "email_sent": email_sent}


@app.post("/admin/license/batch")
async def admin_batch_licenses(
    file: UploadFile = File(...), plan: str = Form("monthly"),
    send_emails: str = Form("true"), admin_key: str = Form(...),
):
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    content = await file.read()
    text = content.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text))
    first_row = next(reader, None)
    if not first_row:
        raise HTTPException(status_code=400, detail="Empty CSV file")
    email_col = 0
    is_header = False
    for i, col in enumerate(first_row):
        if col.strip().lower() in ("email", "e-mail", "email_address", "endereco"):
            email_col = i
            is_header = True
            break
    emails = []
    if not is_header:
        ev = first_row[email_col].strip().lower() if len(first_row) > email_col else ""
        if ev and "@" in ev:
            emails.append(ev)
    for row in reader:
        if len(row) > email_col:
            ev = row[email_col].strip().lower()
            if ev and "@" in ev:
                emails.append(ev)
    should_send = send_emails.lower() in ("true", "1", "yes", "sim")
    results = []
    for em in emails:
        key = generate_license_key()
        await db.licenses.insert_one({
            "key": key, "email": em, "plan": plan, "status": "pending",
            "machine_id": None, "created_at": datetime.now(timezone.utc), "activated_at": None,
        })
        es = False
        if should_send:
            es = await send_license_email(em, key, plan)
        results.append({"email": em, "license_key": key, "email_sent": es})
    return {"success": True, "total": len(results), "results": results}


@app.get("/admin/licenses")
async def admin_list_licenses(status: Optional[str] = None, admin: bool = Depends(verify_admin)):
    query = {}
    if status:
        query["status"] = status
    docs = await db.licenses.find(query).sort("created_at", -1).to_list(length=1000)
    results = []
    for doc in docs:
        results.append({
            "key": doc["key"], "email": doc.get("email", ""), "plan": doc.get("plan", ""),
            "status": doc.get("status", "pending"), "machine_id": doc.get("machine_id"),
            "created_at": doc.get("created_at", "").isoformat() if doc.get("created_at") else None,
            "activated_at": doc.get("activated_at", "").isoformat() if doc.get("activated_at") else None,
        })
    return {"success": True, "total": len(results), "licenses": results}


@app.delete("/admin/license/{license_key}")
async def admin_revoke_license(license_key: str, admin: bool = Depends(verify_admin)):
    result = await db.licenses.update_one(
        {"key": license_key.upper()},
        {"$set": {"status": "revoked", "revoked_at": datetime.now(timezone.utc)}},
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="License key not found")
    return {"success": True, "message": f"License {license_key} revoked"}


# --- Health ---
@app.get("/health")
async def health():
    try:
        await client.admin.command("ping")
        return {
            "status": "ok",
            "database": "connected",
            "email_configured": bool(BREVO_API_KEY or RESEND_API_KEY or (SMTP_USER and SMTP_PASSWORD)),
            "email_provider": "brevo" if BREVO_API_KEY else ("resend" if RESEND_API_KEY else ("smtp" if SMTP_USER else "none")),
        }
    except Exception:
        return {"status": "ok", "database": "disconnected", "email_configured": bool(BREVO_API_KEY or RESEND_API_KEY or (SMTP_USER and SMTP_PASSWORD))}


@app.get("/")
async def root():
    return {"app": "Medical Safe Gold API", "version": "2.0.0", "status": "running"}
