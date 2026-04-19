"""Medical Safe Gold - Secure Backend API"""

import os
import csv
import io
import uuid
import base64
import asyncio
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from typing import Optional, List

import bcrypt
import hashlib
import hmac
from bson import ObjectId
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, HTMLResponse
from jose import jwt, JWTError
import mercadopago
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, field_validator

# --- Configuration ---
MONGO_URI = os.environ.get("MONGO_URI", "")
MASTER_KEY = os.environ.get("MASTER_KEY", "")
MP_ACCESS_TOKEN = os.environ.get("MP_ACCESS_TOKEN", "")
BACKEND_URL = os.environ.get("BACKEND_URL", "https://web-production-2043d.up.railway.app")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://medicalsafegold.com")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is required. Set it before starting the server.")
if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY environment variable is required. Set it before starting the server.")
# Derive JWT_SECRET from MASTER_KEY so it stays consistent across server restarts
_default_jwt = hashlib.sha256(MASTER_KEY.encode()).hexdigest()
JWT_SECRET = os.environ.get("JWT_SECRET", _default_jwt)
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
app = FastAPI(title="Medical Safe Gold API", version="4.0.0")

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
    # Prontuario indexes
    await db.prontuarios.create_index("patient_id")
    await db.prontuarios.create_index("doctor_id")
    await db.prontuarios.create_index("created_at")
    # Access logs indexes
    await db.access_logs.create_index("user_email")
    await db.access_logs.create_index("timestamp")
    # Anexos (exam files) indexes
    await db.anexos.create_index("prontuario_id")
    # Payment orders indexes
    await db.payment_orders.create_index("email")
    await db.payment_orders.create_index("mp_payment_id")
    await db.payment_orders.create_index("preference_id")
    # Confirmacoes indexes
    await db.confirmacoes.create_index("uuid", unique=True)
    await db.confirmacoes.create_index("clinica_id")
    await db.confirmacoes.create_index("appointment_id")
    # Exames indexes
    await db.exames.create_index("prontuario_id")
    await db.exames.create_index("tipo_exame")
    await db.exames.create_index([("prontuario_id", 1), ("tipo_exame", 1)])
    await db.exames.create_index("created_at")


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
    role: str = "receptionist"  # "doctor" or "receptionist"


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


class CreateCheckoutRequest(BaseModel):
    plan: str  # "monthly" or "annual"
    email: str


class AuthResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    fernet_key: Optional[str] = None
    clinica_id: Optional[str] = None
    subscription_status: Optional[str] = None
    subscription_plan: Optional[str] = None
    subscription_expires: Optional[str] = None
    role: Optional[str] = None
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


class ConfirmacaoCreate(BaseModel):
    appointment_id: str
    patient_name: str
    patient_whatsapp: str
    appointment_date: str
    appointment_time: str
    doctor_name: str
    service: str
    clinica_id: str


class ProntuarioCreate(BaseModel):
    patient_id: str
    appointment_id: Optional[str] = None
    sintomas: str
    diagnostico: str
    tratamento: str
    observacoes: Optional[str] = ""
    patient_name: Optional[str] = ""
    patient_cpf: Optional[str] = ""
    encrypted: Optional[bool] = False
    # New v4 fields
    data_nascimento: Optional[str] = ""
    contato: Optional[str] = ""
    historico_clinico: Optional[str] = ""
    anamnese: Optional[str] = ""
    prescricoes: Optional[str] = ""
    cid10_codigo: Optional[str] = ""
    cid10_descricao: Optional[str] = ""


class ProntuarioUpdate(BaseModel):
    sintomas: Optional[str] = None
    diagnostico: Optional[str] = None
    tratamento: Optional[str] = None
    observacoes: Optional[str] = None
    encrypted: Optional[bool] = None
    # New v4 fields
    data_nascimento: Optional[str] = None
    contato: Optional[str] = None
    historico_clinico: Optional[str] = None
    anamnese: Optional[str] = None
    prescricoes: Optional[str] = None
    cid10_codigo: Optional[str] = None
    cid10_descricao: Optional[str] = None


class EvolucaoCreate(BaseModel):
    prontuario_id: Optional[str] = ""  # Optional - taken from URL path
    patient_id: Optional[str] = ""  # Optional - looked up from prontuario
    descricao: Optional[str] = ""  # Main text field
    texto: Optional[str] = ""  # Alias accepted from frontend
    tipo: Optional[str] = "evolucao"  # evolucao, retificacao
    referencia_id: Optional[str] = None  # ID of original record for retificacao
    encrypted: Optional[bool] = False  # Whether the data is encrypted


class RetificacaoCreate(BaseModel):
    motivo: str = ""
    campo: str = ""
    valor_corrigido: str = ""
    descricao: Optional[str] = ""  # Fallback
    prontuario_id: Optional[str] = ""
    patient_id: Optional[str] = ""


class ExameCreate(BaseModel):
    prontuario_id: Optional[str] = ""  # Optional - taken from URL path
    patient_id: Optional[str] = ""  # Optional - looked up from prontuario
    tipo_exame: str  # e.g. "Hemograma", "Glicemia", etc.
    descricao: Optional[str] = ""
    interpretacao: Optional[str] = ""
    data_exame: Optional[str] = ""
    profissional_responsavel: Optional[str] = ""
    
    @field_validator('data_exame')
    @classmethod
    def validate_data_exame(cls, v):
        """Validate exam date format (YYYY-MM-DD)"""
        if v and v.strip():
            try:
                datetime.strptime(v, '%Y-%m-%d')
            except ValueError:
                raise ValueError('data_exame must be in format YYYY-MM-DD')
        return v


class ExameUpdate(BaseModel):
    tipo_exame: Optional[str] = None
    descricao: Optional[str] = None
    interpretacao: Optional[str] = None
    data_exame: Optional[str] = None
    profissional_responsavel: Optional[str] = None


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


async def verify_doctor(email: str = Depends(verify_token)) -> str:
    """Verify user is authenticated AND has doctor role."""
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("role", "doctor") != "doctor":
        raise HTTPException(status_code=403, detail="ACCESS_DENIED_DOCTOR_ONLY")
    return email


async def log_access(user_email: str, action: str, prontuario_id: str = "", details: str = "", request: Optional[Request] = None):
    """Log access to prontuario data for LGPD compliance. Immutable audit trail."""
    client_ip = ""
    if request:
        client_ip = request.client.host if request.client else ""
    # Insert into immutable audit_trail collection (no delete endpoint exists)
    log_doc = {
        "user_email": user_email,
        "action": action,
        "prontuario_id": prontuario_id,
        "details": details,
        "ip": client_ip,
        "timestamp": datetime.now(timezone.utc),
    }
    await db.access_logs.insert_one(log_doc)
    # Also insert into immutable audit_trail (separate collection, never deleted)
    await db.audit_trail.insert_one(log_doc.copy())


def compute_integrity_hash(data: dict) -> str:
    """Compute SHA-256 hash for data integrity verification."""
    # Create a deterministic string from key clinical fields
    fields = ["sintomas", "diagnostico", "tratamento", "observacoes",
              "anamnese", "historico_clinico", "prescricoes",
              "cid10_codigo", "cid10_descricao"]
    content = "|".join(str(data.get(f, "")) for f in fields)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def is_editable(created_at: datetime) -> bool:
    """Check if a prontuario record is still editable.
    Records can only be edited on the same calendar day (UTC) they were created.
    After midnight UTC of the creation day, they become read-only."""
    if not created_at:
        return False
    now = datetime.now(timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return now.date() == created_at.date()


def validate_object_id(id_str: str, entity_name: str = "Record") -> ObjectId:
    """Validate and convert a string to ObjectId, raising 400 if invalid."""
    from bson.errors import InvalidId
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail=f"ID inválido para {entity_name}: {id_str}")


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
    if license_doc.get("status") == "revoked":
        return AuthResponse(success=False, error="LICENSE_REVOKED")

    existing = await db.users.find_one({"email": email})
    if existing:
        return AuthResponse(success=False, error="USER_EXISTS")

    # If license is already activated, allow additional users (e.g. receptionist)
    # but use the original doctor's email as clinica_id so they share data
    clinica_id = email
    original_fernet_key = None
    if license_doc.get("status") == "activated":
        # Find the original user who activated this license to share clinic
        original_user = await db.users.find_one({"license_key": license_key})
        if original_user:
            clinica_id = original_user["email"]
            # Share the same Fernet key so both users can decrypt the same data
            try:
                original_fernet_key = decrypt_user_key(original_user["fernet_key_encrypted"])
            except Exception:
                pass

    password_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt(10))
    if original_fernet_key:
        user_fernet_key = original_fernet_key
    else:
        user_fernet_key = generate_user_fernet_key()
    encrypted_fernet_key = encrypt_user_key(user_fernet_key)

    plan = license_doc.get("plan", "monthly")
    if plan == "monthly":
        expires = datetime.now(timezone.utc) + timedelta(days=30)
    elif plan == "annual":
        expires = datetime.now(timezone.utc) + timedelta(days=365)
    else:
        expires = datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)

    # Validate role
    role = req.role.strip().lower() if req.role else "doctor"
    if role not in ("doctor", "receptionist"):
        return AuthResponse(success=False, error="INVALID_ROLE")

    await db.users.insert_one({
        "email": email,
        "password_hash": password_hash.decode() if isinstance(password_hash, bytes) else password_hash,
        "machine_id": req.machine_id,
        "fernet_key_encrypted": encrypted_fernet_key,
        "license_key": license_key,
        "clinica_id": clinica_id,
        "role": role,
        "subscription_status": "active",
        "subscription_plan": plan,
        "subscription_expires": expires,
        "created_at": datetime.now(timezone.utc),
        "last_login": datetime.now(timezone.utc),
    })

    # Bind machine_id to license on first activation
    if license_doc.get("status") != "activated":
        await db.licenses.update_one(
            {"key": license_key},
            {"$set": {
                "status": "activated", "email": email,
                "machine_id": req.machine_id, "activated_at": datetime.now(timezone.utc),
            }},
        )

    token = create_jwt_token(email)
    return AuthResponse(
        success=True, token=token, fernet_key=user_fernet_key, clinica_id=clinica_id,
        subscription_status="active", subscription_plan=plan, subscription_expires=expires.isoformat(),
        role=role,
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

    # Use stored clinica_id if available, otherwise fall back to email
    clinica_id = user.get("clinica_id", email)

    return AuthResponse(
        success=True,
        token=token,
        fernet_key=user_fernet_key,
        clinica_id=clinica_id,
        subscription_status=user.get("subscription_status", "trial"),
        subscription_plan=user.get("subscription_plan"),
        subscription_expires=user.get("subscription_expires", "").isoformat()
        if user.get("subscription_expires")
        else None,
        role=user.get("role", "doctor"),
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
    from bson.errors import InvalidId

    try:
        oid = ObjectId(appointment_id)
    except (InvalidId, Exception):
        raise HTTPException(status_code=400, detail="Invalid appointment ID")

    result = await db.agendamentos.delete_one({
        "_id": oid,
        "clinica_id": clinica_id,
    })
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found")
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


# --- Mercado Pago Payment Endpoints ---
def _get_mp_sdk():
    """Get Mercado Pago SDK instance."""
    if not MP_ACCESS_TOKEN:
        raise HTTPException(status_code=500, detail="Mercado Pago not configured (MP_ACCESS_TOKEN missing)")
    return mercadopago.SDK(MP_ACCESS_TOKEN)


@app.post("/payments/create-preference")
async def create_payment_preference(req: CreateCheckoutRequest):
    """Create a Mercado Pago checkout preference for a plan."""
    sdk = _get_mp_sdk()
    email = req.email.strip().lower()

    if req.plan == "monthly":
        title = "Medical Safe Gold - Assinatura Mensal"
        price = 69.00
        plan_label = "monthly"
    elif req.plan == "annual":
        title = "Medical Safe Gold - Plano Anual"
        price = 549.00
        plan_label = "annual"
    else:
        raise HTTPException(status_code=400, detail="Invalid plan. Use 'monthly' or 'annual'.")

    preference_data = {
        "items": [
            {
                "title": title,
                "quantity": 1,
                "unit_price": price,
                "currency_id": "BRL",
            }
        ],
        "payer": {
            "email": email,
        },
        "back_urls": {
            "success": f"{BACKEND_URL}/payments/success?plan={plan_label}&email={urllib.parse.quote_plus(email)}",
            "failure": f"{FRONTEND_URL}/#pricing",
            "pending": f"{BACKEND_URL}/payments/pending?plan={plan_label}&email={urllib.parse.quote_plus(email)}",
        },
        "auto_return": "approved",
        "notification_url": f"{BACKEND_URL}/payments/webhook",
        "external_reference": f"{email}|{plan_label}",
        "statement_descriptor": "MEDICALSAFEGOLD",
    }

    result = sdk.preference().create(preference_data)
    if result["status"] == 201:
        preference = result["response"]
        # Store the preference in DB for tracking
        await db.payment_orders.insert_one({
            "preference_id": preference["id"],
            "email": email,
            "plan": plan_label,
            "amount": price,
            "status": "created",
            "created_at": datetime.now(timezone.utc),
        })
        return {
            "success": True,
            "checkout_url": preference["init_point"],
            "preference_id": preference["id"],
        }
    else:
        raise HTTPException(status_code=500, detail=f"Failed to create preference: {result.get('response', {})}")


@app.post("/payments/webhook")
async def mercadopago_webhook(request: Request):
    """Receive Mercado Pago IPN webhook notifications."""
    try:
        body = await request.json()
    except Exception:
        return {"status": "ok"}

    action = body.get("action", "")
    data_id = body.get("data", {}).get("id")
    topic = body.get("type", "") or request.query_params.get("topic", "")

    # Only process payment notifications
    if topic == "payment" or action == "payment.created" or action == "payment.updated":
        if data_id:
            await _process_payment(str(data_id))

    return {"status": "ok"}


async def _process_payment(payment_id: str):
    """Verify a payment with Mercado Pago API and generate license if approved."""
    try:
        sdk = _get_mp_sdk()
        result = sdk.payment().get(int(payment_id))

        if result["status"] != 200:
            print(f"[MP] Failed to get payment {payment_id}: {result}")
            return

        payment = result["response"]
        status = payment.get("status")
        external_ref = payment.get("external_reference", "")
        payer_email = payment.get("payer", {}).get("email", "")

        # Parse external_reference: "email|plan"
        parts = external_ref.split("|") if external_ref else []
        if len(parts) == 2:
            email = parts[0]
            plan = parts[1]
        else:
            email = payer_email
            plan = "monthly"

        # Atomic deduplication: try to claim this payment_id first
        claim_result = await db.payment_orders.find_one_and_update(
            {"mp_payment_id": str(payment_id), "status": "approved"},
            {"$set": {"mp_payment_id": str(payment_id)}},
        )
        if claim_result:
            print(f"[MP] Payment {payment_id} already processed")
            return

        if status == "approved":
            # Generate license key
            license_key = generate_license_key()

            # Update payment order atomically to claim this payment
            claim = await db.payment_orders.find_one_and_update(
                {"email": email, "plan": plan, "status": {"$ne": "approved"}},
                {
                    "$set": {
                        "status": "approved",
                        "mp_payment_id": str(payment_id),
                        "license_key": license_key,
                        "approved_at": datetime.now(timezone.utc),
                    }
                },
                upsert=True,
                return_document=True,
            )

            # Only insert license if we successfully claimed
            if claim:
                # Check if license already exists for this payment
                existing_license = await db.licenses.find_one({"mp_payment_id": str(payment_id)})
                if not existing_license:
                    await db.licenses.insert_one({
                        "key": license_key,
                        "email": email,
                        "plan": plan,
                        "status": "pending",
                        "machine_id": None,
                        "created_at": datetime.now(timezone.utc),
                        "activated_at": None,
                        "mp_payment_id": str(payment_id),
                    })

                    # Send license email
                    email_sent = await send_license_email(email, license_key, plan)
                    print(f"[MP] Payment {payment_id} approved. License {license_key} generated for {email}. Email sent: {email_sent}")
                else:
                    print(f"[MP] License already exists for payment {payment_id}")

        else:
            # Update payment status
            await db.payment_orders.update_one(
                {"email": email, "plan": plan},
                {"$set": {"status": status, "mp_payment_id": str(payment_id)}},
            )
            print(f"[MP] Payment {payment_id} status: {status}")

    except Exception as e:
        print(f"[MP] Error processing payment {payment_id}: {e}")


@app.get("/payments/success", response_class=HTMLResponse)
async def payment_success(plan: str = "monthly", email: str = ""):
    """Success page after Mercado Pago payment - also processes the payment."""
    # Escape user input to prevent XSS
    email = html_escape(email)
    plan = html_escape(plan)

    plan_name = "Mensal (R$ 69/mes)" if plan == "monthly" else "Anual (R$ 549/ano)"

    html = f"""<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pagamento Aprovado - Medical Safe Gold</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: 'Inter', -apple-system, sans-serif;
      background: #0a0a0f;
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .container {{
      text-align: center;
      max-width: 600px;
      padding: 40px 24px;
    }}
    .icon {{
      width: 80px; height: 80px;
      background: linear-gradient(135deg, #45c97a, #2a9d5c);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 24px;
      font-size: 40px;
    }}
    h1 {{
      font-size: 32px;
      color: #d4af37;
      margin-bottom: 16px;
    }}
    p {{
      color: #8888a0;
      font-size: 16px;
      line-height: 1.6;
      margin-bottom: 12px;
    }}
    .highlight {{
      color: #d4af37;
      font-weight: 700;
    }}
    .info-box {{
      background: #13131d;
      border: 1px solid rgba(212,175,55,0.2);
      border-radius: 12px;
      padding: 24px;
      margin: 24px 0;
    }}
    .info-box p {{
      margin-bottom: 8px;
    }}
    .btn {{
      display: inline-block;
      background: linear-gradient(135deg, #d4af37, #b8960c);
      color: #0a0a0f;
      padding: 14px 32px;
      border-radius: 10px;
      font-size: 16px;
      font-weight: 700;
      text-decoration: none;
      margin-top: 20px;
      transition: all 0.3s;
    }}
    .btn:hover {{
      transform: translateY(-2px);
      box-shadow: 0 4px 20px rgba(212,175,55,0.3);
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">&#10003;</div>
    <h1>Pagamento Aprovado!</h1>
    <div class="info-box">
      <p><strong>Plano:</strong> <span class="highlight">{plan_name}</span></p>
      <p><strong>E-mail:</strong> <span class="highlight">{email}</span></p>
      <p style="margin-top:16px;color:#45c97a;font-weight:600;">Sua chave de licenca foi enviada para o seu e-mail!</p>
      <p style="font-size:14px;">Verifique sua caixa de entrada e a pasta de spam.</p>
    </div>
    <p>Use a chave de licenca recebida por e-mail para cadastrar sua conta no aplicativo Medical Safe Gold.</p>
    <a href="{FRONTEND_URL}" class="btn">Voltar ao Site</a>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@app.get("/payments/pending", response_class=HTMLResponse)
async def payment_pending(plan: str = "monthly", email: str = ""):
    """Pending payment page."""
    # Escape user input to prevent XSS
    email = html_escape(email)
    plan = html_escape(plan)

    html = f"""<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pagamento Pendente - Medical Safe Gold</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: 'Inter', -apple-system, sans-serif;
      background: #0a0a0f;
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .container {{
      text-align: center;
      max-width: 600px;
      padding: 40px 24px;
    }}
    .icon {{
      width: 80px; height: 80px;
      background: linear-gradient(135deg, #ffbd2e, #e6a820);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 24px;
      font-size: 40px;
    }}
    h1 {{ font-size: 32px; color: #ffbd2e; margin-bottom: 16px; }}
    p {{ color: #8888a0; font-size: 16px; line-height: 1.6; margin-bottom: 12px; }}
    .btn {{
      display: inline-block;
      background: linear-gradient(135deg, #d4af37, #b8960c);
      color: #0a0a0f;
      padding: 14px 32px;
      border-radius: 10px;
      font-size: 16px;
      font-weight: 700;
      text-decoration: none;
      margin-top: 20px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">&#8987;</div>
    <h1>Pagamento Pendente</h1>
    <p>Seu pagamento esta sendo processado. Assim que for aprovado, voce recebera sua chave de licenca no e-mail <strong style="color:#d4af37;">{email}</strong>.</p>
    <p>Se estiver usando boleto, pode levar ate 2 dias uteis.</p>
    <a href="{FRONTEND_URL}" class="btn">Voltar ao Site</a>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


@app.get("/payments/check/{email_addr}")
async def check_payment_status(email_addr: str):
    """Check if a payment/license exists for an email (public endpoint for landing page)."""
    email = email_addr.strip().lower()
    order = await db.payment_orders.find_one(
        {"email": email, "status": "approved"},
        sort=[("approved_at", -1)],
    )
    if order:
        return {
            "paid": True,
            "plan": order.get("plan"),
        }
    return {"paid": False}


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
    return {"app": "Medical Safe Gold API", "version": "3.0.0", "status": "running"}


# --- Prontuario Endpoints (Doctor Only) ---

@app.post("/prontuarios")
async def create_prontuario(
    data: ProntuarioCreate,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Create a new prontuario (medical record). Doctor only."""
    doc = {
        "patient_id": data.patient_id,
        "appointment_id": data.appointment_id or "",
        "doctor_id": email,
        "sintomas": data.sintomas,
        "diagnostico": data.diagnostico,
        "tratamento": data.tratamento,
        "observacoes": data.observacoes or "",
        "patient_name": data.patient_name or "",
        "patient_cpf": data.patient_cpf or "",
        "encrypted": data.encrypted or False,
        # New v4 fields
        "data_nascimento": data.data_nascimento or "",
        "contato": data.contato or "",
        "historico_clinico": data.historico_clinico or "",
        "anamnese": data.anamnese or "",
        "prescricoes": data.prescricoes or "",
        "cid10_codigo": data.cid10_codigo or "",
        "cid10_descricao": data.cid10_descricao or "",
        "anexos": [],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    # Compute integrity hash for tamper detection
    doc["integrity_hash"] = compute_integrity_hash(doc)
    # Digital signature preparation: store signing metadata
    doc["assinatura"] = {
        "doctor_email": email,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "hash": doc["integrity_hash"],
    }
    result = await db.prontuarios.insert_one(doc)
    await log_access(email, "CREATE_PRONTUARIO", str(result.inserted_id), f"patient={data.patient_id}", request)
    return {"success": True, "id": str(result.inserted_id)}


@app.get("/prontuarios/anexo/{anexo_id}")
async def get_anexo(
    anexo_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Get an attached file by ID. Doctor only."""
    doc = await db.anexos.find_one({"_id": ObjectId(anexo_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Anexo not found")

    await log_access(email, "VIEW_ANEXO", doc.get("prontuario_id", ""), f"file={doc.get('filename')}", request)

    file_data = base64.b64decode(doc["data"])
    return Response(
        content=file_data,
        media_type=doc.get("content_type", "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{doc.get("filename", "arquivo").replace(chr(34), "_").replace(chr(92), "_").replace(chr(10), "").replace(chr(13), "")}"'},
    )


@app.get("/prontuarios/anexos/{prontuario_id}")
async def list_anexos(
    prontuario_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """List all anexos for a prontuario (metadata only, no file data). Doctor only."""
    docs = await db.anexos.find(
        {"prontuario_id": prontuario_id},
        {"data": 0},  # Exclude file data for performance
    ).to_list(length=100)
    results = []
    for doc in docs:
        results.append({
            "id": str(doc["_id"]),
            "filename": doc.get("filename", ""),
            "content_type": doc.get("content_type", ""),
            "size": doc.get("size", 0),
            "descricao": doc.get("descricao", ""),
            "uploaded_by": doc.get("uploaded_by", ""),
            "uploaded_at": doc["uploaded_at"].isoformat() if doc.get("uploaded_at") else None,
        })
    await log_access(email, "LIST_ANEXOS", prontuario_id, f"count={len(results)}", request)
    return {"success": True, "data": results}


@app.delete("/prontuarios/anexo/{anexo_id}")
async def delete_anexo(
    anexo_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Delete an attached file. Doctor only."""
    doc = await db.anexos.find_one({"_id": ObjectId(anexo_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Anexo not found")

    prontuario_id = doc.get("prontuario_id", "")
    await db.anexos.delete_one({"_id": ObjectId(anexo_id)})

    # Remove reference from prontuario
    if prontuario_id:
        await db.prontuarios.update_one(
            {"_id": ObjectId(prontuario_id)},
            {
                "$pull": {"anexos": {"id": anexo_id}},
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
        )
    await log_access(email, "DELETE_ANEXO", prontuario_id, f"file={doc.get('filename')}", request)
    return {"success": True}


def _serialize_prontuario(doc: dict) -> dict:
    """Serialize a prontuario document for API response, including v4 fields."""
    anexo_count = len(doc.get("anexos", []))
    created_at = doc.get("created_at")
    return {
        "id": str(doc["_id"]),
        "patient_id": doc["patient_id"],
        "appointment_id": doc.get("appointment_id", ""),
        "doctor_id": doc["doctor_id"],
        "sintomas": doc["sintomas"],
        "diagnostico": doc["diagnostico"],
        "tratamento": doc["tratamento"],
        "observacoes": doc.get("observacoes", ""),
        "patient_name": doc.get("patient_name", ""),
        "patient_cpf": doc.get("patient_cpf", ""),
        "encrypted": doc.get("encrypted", False),
        # v4 fields
        "data_nascimento": doc.get("data_nascimento", ""),
        "contato": doc.get("contato", ""),
        "historico_clinico": doc.get("historico_clinico", ""),
        "anamnese": doc.get("anamnese", ""),
        "prescricoes": doc.get("prescricoes", ""),
        "cid10_codigo": doc.get("cid10_codigo", ""),
        "cid10_descricao": doc.get("cid10_descricao", ""),
        "integrity_hash": doc.get("integrity_hash", ""),
        "assinatura": doc.get("assinatura"),
        "locked": not is_editable(created_at) if created_at else False,
        "anexo_count": anexo_count,
        "created_at": doc["created_at"].isoformat() if doc.get("created_at") else None,
        "updated_at": doc["updated_at"].isoformat() if doc.get("updated_at") else None,
    }


@app.get("/prontuarios/search")
async def search_prontuarios(
    q: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Search prontuarios by patient name, CPF, or ID (partial, case-insensitive). Doctor only."""
    import re
    safe_q = re.escape(q.strip())
    if not safe_q:
        return {"success": True, "data": []}
    regex = {"$regex": safe_q, "$options": "i"}
    query = {"$or": [
        {"patient_name": regex},
        {"patient_cpf": regex},
        {"patient_id": regex},
    ]}
    docs = await db.prontuarios.find(query).sort("created_at", -1).to_list(length=200)
    results = [_serialize_prontuario(doc) for doc in docs]
    await log_access(email, "SEARCH_PRONTUARIOS", "", f"query={q}, count={len(results)}", request)
    return {"success": True, "data": results}


@app.get("/prontuarios/{patient_id}")
async def get_prontuarios(
    patient_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Get all prontuarios for a patient. Doctor only."""
    docs = await db.prontuarios.find({"patient_id": patient_id}).sort("created_at", -1).to_list(length=1000)
    results = [_serialize_prontuario(doc) for doc in docs]
    await log_access(email, "VIEW_PRONTUARIOS", "", f"patient={patient_id}, count={len(results)}", request)
    return {"success": True, "data": results}


@app.put("/prontuarios/{prontuario_id}")
async def update_prontuario(
    prontuario_id: str,
    data: ProntuarioUpdate,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Update a prontuario. Doctor only. Blocked after midnight of creation day."""
    # Fetch existing record to check editability
    existing = await db.prontuarios.find_one({"_id": ObjectId(prontuario_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Prontuario not found")

    created_at = existing.get("created_at")
    if created_at and not is_editable(created_at):
        await log_access(email, "UPDATE_PRONTUARIO_BLOCKED", prontuario_id,
                         "Edit blocked: record locked after midnight", request)
        raise HTTPException(
            status_code=403,
            detail="Prontuário bloqueado para edição. Registros só podem ser editados no mesmo dia da criação. Use o sistema de retificação para correções."
        )

    update_fields = {"updated_at": datetime.now(timezone.utc)}
    for field_name in ["sintomas", "diagnostico", "tratamento", "observacoes",
                       "data_nascimento", "contato", "historico_clinico",
                       "anamnese", "prescricoes", "cid10_codigo", "cid10_descricao"]:
        value = getattr(data, field_name, None)
        if value is not None:
            update_fields[field_name] = value
    if data.encrypted is not None:
        update_fields["encrypted"] = data.encrypted

    # Recompute integrity hash with merged data
    merged = {**existing, **update_fields}
    update_fields["integrity_hash"] = compute_integrity_hash(merged)

    result = await db.prontuarios.update_one(
        {"_id": ObjectId(prontuario_id)},
        {"$set": update_fields},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Prontuario not found")
    await log_access(email, "UPDATE_PRONTUARIO", prontuario_id, "", request)
    return {"success": True}


@app.delete("/prontuarios/{prontuario_id}")
async def delete_prontuario(
    prontuario_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Prontuário deletion is PROHIBITED. Medical records must be retained for 20+ years."""
    await log_access(email, "DELETE_PRONTUARIO_BLOCKED", prontuario_id,
                     "Deletion attempt blocked: medical records cannot be deleted", request)
    raise HTTPException(
        status_code=403,
        detail="Exclusão de prontuários é proibida. Registros médicos devem ser mantidos por no mínimo 20 anos conforme legislação vigente."
    )


# --- Evoluções (Medical Evolutions - Append Only) ---

@app.post("/prontuarios/{prontuario_id}/evolucoes")
async def create_evolucao(
    prontuario_id: str,
    data: EvolucaoCreate,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Add a medical evolution to a prontuario. Append-only, cannot be edited or deleted."""
    # Verify prontuario exists
    oid = validate_object_id(prontuario_id, "Prontuário")
    pront = await db.prontuarios.find_one({"_id": oid})
    if not pront:
        raise HTTPException(status_code=404, detail="Prontuario not found")

    # Accept 'texto' as alias for 'descricao' (frontend sends 'texto')
    descricao = data.descricao or data.texto or ""
    patient_id = data.patient_id or str(pront.get("patient_id", ""))

    doc = {
        "prontuario_id": prontuario_id,
        "patient_id": patient_id,
        "doctor_id": email,
        "descricao": descricao,
        "texto": descricao,  # Store both for frontend compatibility
        "created_by": email,
        "tipo": data.tipo or "evolucao",
        "referencia_id": data.referencia_id or "",
        "created_at": datetime.now(timezone.utc),
        "integrity_hash": hashlib.sha256(descricao.encode("utf-8")).hexdigest(),
    }
    result = await db.evolucoes.insert_one(doc)
    await log_access(email, "CREATE_EVOLUCAO", prontuario_id, f"tipo={data.tipo}", request)
    return {"success": True, "id": str(result.inserted_id)}


@app.get("/prontuarios/{prontuario_id}/evolucoes")
async def list_evolucoes(
    prontuario_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """List all evolutions for a prontuario (chronological, append-only). Doctor only."""
    docs = await db.evolucoes.find({"prontuario_id": prontuario_id}).sort("created_at", 1).to_list(length=1000)
    results = []
    for doc in docs:
        results.append({
            "id": str(doc["_id"]),
            "prontuario_id": doc["prontuario_id"],
            "patient_id": doc.get("patient_id", ""),
            "doctor_id": doc["doctor_id"],
            "descricao": doc["descricao"],
            "tipo": doc.get("tipo", "evolucao"),
            "referencia_id": doc.get("referencia_id", ""),
            "integrity_hash": doc.get("integrity_hash", ""),
            "created_at": doc["created_at"].isoformat() if doc.get("created_at") else None,
        })
    await log_access(email, "LIST_EVOLUCOES", prontuario_id, f"count={len(results)}", request)
    return {"success": True, "data": results}


# --- Exames (Exams within Prontuario) ---

@app.post("/prontuarios/{prontuario_id}/exames")
async def create_exame(
    prontuario_id: str,
    data: ExameCreate,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Add an exam record to a prontuario. Doctor only."""
    oid = validate_object_id(prontuario_id, "Prontuário")
    pront = await db.prontuarios.find_one({"_id": oid})
    if not pront:
        raise HTTPException(status_code=404, detail="Prontuario not found")

    # Use patient_id from body or look up from prontuario
    patient_id = data.patient_id or str(pront.get("patient_id", ""))

    doc = {
        "prontuario_id": prontuario_id,
        "patient_id": patient_id,
        "doctor_id": email,
        "tipo_exame": data.tipo_exame,
        "descricao": data.descricao or "",
        "interpretacao": data.interpretacao or "",
        "data_exame": data.data_exame or "",
        "profissional_responsavel": data.profissional_responsavel or email,
        "anexos": [],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = await db.exames.insert_one(doc)
    await log_access(email, "CREATE_EXAME", prontuario_id, f"tipo={data.tipo_exame}", request)
    return {"success": True, "id": str(result.inserted_id)}


@app.get("/prontuarios/{prontuario_id}/exames")
async def list_exames(
    prontuario_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """List all exams for a prontuario, ordered by date. Doctor only."""
    docs = await db.exames.find({"prontuario_id": prontuario_id}).sort("created_at", -1).to_list(length=500)
    results = []
    for doc in docs:
        results.append({
            "id": str(doc["_id"]),
            "prontuario_id": doc["prontuario_id"],
            "patient_id": doc.get("patient_id", ""),
            "doctor_id": doc["doctor_id"],
            "tipo_exame": doc["tipo_exame"],
            "descricao": doc.get("descricao", ""),
            "interpretacao": doc.get("interpretacao", ""),
            "data_exame": doc.get("data_exame", ""),
            "profissional_responsavel": doc.get("profissional_responsavel", ""),
            "anexos": doc.get("anexos", []),
            "created_at": doc["created_at"].isoformat() if doc.get("created_at") else None,
            "updated_at": doc["updated_at"].isoformat() if doc.get("updated_at") else None,
        })
    await log_access(email, "LIST_EXAMES", prontuario_id, f"count={len(results)}", request)
    return {"success": True, "data": results}


@app.put("/prontuarios/{prontuario_id}/exames/{exame_id}")
async def update_exame(
    prontuario_id: str,
    exame_id: str,
    data: ExameUpdate,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Update an exam record. Doctor only."""
    validate_object_id(prontuario_id, "Prontuário")
    exame_oid = validate_object_id(exame_id, "Exame")
    update_fields = {"updated_at": datetime.now(timezone.utc)}
    for field_name in ["tipo_exame", "descricao", "interpretacao", "data_exame", "profissional_responsavel"]:
        value = getattr(data, field_name, None)
        if value is not None:
            update_fields[field_name] = value

    result = await db.exames.update_one(
        {"_id": exame_oid, "prontuario_id": prontuario_id},
        {"$set": update_fields},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Exame not found")
    await log_access(email, "UPDATE_EXAME", prontuario_id, f"exame={exame_id}", request)
    return {"success": True}


@app.delete("/prontuarios/{prontuario_id}/exames/{exame_id}")
async def delete_exame(
    prontuario_id: str,
    exame_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Exame deletion is PROHIBITED. Clinical data must be retained."""
    await log_access(email, "DELETE_EXAME_BLOCKED", prontuario_id,
                     f"Deletion attempt blocked for exame={exame_id}", request)
    raise HTTPException(
        status_code=403,
        detail="Exclusão de exames é proibida. Dados clínicos devem ser mantidos conforme legislação vigente."
    )


# --- CID-10 (International Classification of Diseases) ---

CID10_DATA = [
    {"codigo": "A00", "descricao": "Cólera"},
    {"codigo": "A01", "descricao": "Febres tifóide e paratifóide"},
    {"codigo": "A09", "descricao": "Diarreia e gastroenterite de origem infecciosa presumível"},
    {"codigo": "A15", "descricao": "Tuberculose respiratória"},
    {"codigo": "A90", "descricao": "Dengue"},
    {"codigo": "B15", "descricao": "Hepatite aguda A"},
    {"codigo": "B24", "descricao": "Doença pelo vírus da imunodeficiência humana (HIV)"},
    {"codigo": "B34", "descricao": "Infecção viral não especificada"},
    {"codigo": "C50", "descricao": "Neoplasia maligna da mama"},
    {"codigo": "C61", "descricao": "Neoplasia maligna da próstata"},
    {"codigo": "D50", "descricao": "Anemia por deficiência de ferro"},
    {"codigo": "E10", "descricao": "Diabetes mellitus insulino-dependente (Tipo 1)"},
    {"codigo": "E11", "descricao": "Diabetes mellitus não insulino-dependente (Tipo 2)"},
    {"codigo": "E66", "descricao": "Obesidade"},
    {"codigo": "E78", "descricao": "Distúrbios do metabolismo de lipoproteínas (Dislipidemia)"},
    {"codigo": "F10", "descricao": "Transtornos mentais por uso de álcool"},
    {"codigo": "F20", "descricao": "Esquizofrenia"},
    {"codigo": "F31", "descricao": "Transtorno afetivo bipolar"},
    {"codigo": "F32", "descricao": "Episódio depressivo"},
    {"codigo": "F41", "descricao": "Outros transtornos ansiosos"},
    {"codigo": "G40", "descricao": "Epilepsia"},
    {"codigo": "G43", "descricao": "Enxaqueca"},
    {"codigo": "H10", "descricao": "Conjuntivite"},
    {"codigo": "H66", "descricao": "Otite média supurativa e não especificada"},
    {"codigo": "I10", "descricao": "Hipertensão essencial (primária)"},
    {"codigo": "I20", "descricao": "Angina pectoris"},
    {"codigo": "I21", "descricao": "Infarto agudo do miocárdio"},
    {"codigo": "I50", "descricao": "Insuficiência cardíaca"},
    {"codigo": "I64", "descricao": "Acidente vascular cerebral (AVC)"},
    {"codigo": "J00", "descricao": "Nasofaringite aguda (Resfriado comum)"},
    {"codigo": "J02", "descricao": "Faringite aguda"},
    {"codigo": "J03", "descricao": "Amigdalite aguda"},
    {"codigo": "J06", "descricao": "Infecções agudas das vias aéreas superiores"},
    {"codigo": "J11", "descricao": "Influenza (Gripe)"},
    {"codigo": "J18", "descricao": "Pneumonia"},
    {"codigo": "J30", "descricao": "Rinite alérgica e vasomotora"},
    {"codigo": "J45", "descricao": "Asma"},
    {"codigo": "K21", "descricao": "Doença de refluxo gastroesofágico"},
    {"codigo": "K25", "descricao": "Úlcera gástrica"},
    {"codigo": "K29", "descricao": "Gastrite e duodenite"},
    {"codigo": "K35", "descricao": "Apendicite aguda"},
    {"codigo": "K40", "descricao": "Hérnia inguinal"},
    {"codigo": "K80", "descricao": "Colelitíase (Pedra na vesícula)"},
    {"codigo": "L20", "descricao": "Dermatite atópica"},
    {"codigo": "L50", "descricao": "Urticária"},
    {"codigo": "M15", "descricao": "Poliartrose"},
    {"codigo": "M25", "descricao": "Outros transtornos articulares"},
    {"codigo": "M54", "descricao": "Dorsalgia (Dor nas costas)"},
    {"codigo": "M79", "descricao": "Reumatismo não especificado (Fibromialgia)"},
    {"codigo": "N10", "descricao": "Nefrite túbulo-intersticial aguda (Infecção renal)"},
    {"codigo": "N20", "descricao": "Cálculo do rim e do ureter (Pedra nos rins)"},
    {"codigo": "N30", "descricao": "Cistite (Infecção urinária)"},
    {"codigo": "N39", "descricao": "Outros transtornos do trato urinário"},
    {"codigo": "N76", "descricao": "Outras inflamações da vagina e vulva"},
    {"codigo": "O80", "descricao": "Parto único espontâneo"},
    {"codigo": "R05", "descricao": "Tosse"},
    {"codigo": "R10", "descricao": "Dor abdominal e pélvica"},
    {"codigo": "R11", "descricao": "Náusea e vômitos"},
    {"codigo": "R50", "descricao": "Febre de origem desconhecida"},
    {"codigo": "R51", "descricao": "Cefaleia (Dor de cabeça)"},
    {"codigo": "S00", "descricao": "Traumatismo superficial da cabeça"},
    {"codigo": "S52", "descricao": "Fratura do antebraço"},
    {"codigo": "S82", "descricao": "Fratura da perna, incluindo tornozelo"},
    {"codigo": "T14", "descricao": "Traumatismo de região não especificada"},
    {"codigo": "T78", "descricao": "Efeitos adversos não classificados em outra parte (Alergia)"},
    {"codigo": "Z00", "descricao": "Exame geral e investigação (Check-up)"},
    {"codigo": "Z01", "descricao": "Outros exames especiais e investigações"},
    {"codigo": "Z34", "descricao": "Supervisão de gravidez normal"},
    {"codigo": "Z76", "descricao": "Pessoas em contato com serviços de saúde (Atestado)"},
]


@app.get("/cid10")
async def list_cid10(q: Optional[str] = None):
    """List CID-10 codes with optional search/autocomplete. Public endpoint."""
    if q:
        q_lower = q.lower()
        filtered = [c for c in CID10_DATA
                    if q_lower in c["codigo"].lower() or q_lower in c["descricao"].lower()]
        return {"success": True, "data": filtered}
    return {"success": True, "data": CID10_DATA}


# --- Retificação (Correction without altering original) ---

@app.post("/prontuarios/{prontuario_id}/retificacao")
async def create_retificacao(
    prontuario_id: str,
    data: RetificacaoCreate,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Create a retification record for a locked prontuario. Does not alter the original."""
    oid = validate_object_id(prontuario_id, "Prontuário")
    pront = await db.prontuarios.find_one({"_id": oid})
    if not pront:
        raise HTTPException(status_code=404, detail="Prontuario not found")

    # Build description from retificacao fields (frontend sends motivo/campo/valor_corrigido)
    descricao = data.descricao or f"Campo: {data.campo} | Motivo: {data.motivo} | Valor corrigido: {data.valor_corrigido}"
    patient_id = data.patient_id or str(pront.get("patient_id", ""))

    doc = {
        "prontuario_id": prontuario_id,
        "patient_id": patient_id,
        "doctor_id": email,
        "descricao": descricao,
        "motivo": data.motivo,
        "campo": data.campo,
        "valor_corrigido": data.valor_corrigido,
        "tipo": "retificacao",
        "referencia_id": prontuario_id,
        "created_at": datetime.now(timezone.utc),
        "integrity_hash": hashlib.sha256(descricao.encode("utf-8")).hexdigest(),
    }
    result = await db.evolucoes.insert_one(doc)
    await log_access(email, "CREATE_RETIFICACAO", prontuario_id, f"retificacao_id={result.inserted_id}", request)
    return {"success": True, "id": str(result.inserted_id)}


# --- Integrity Verification ---

@app.get("/prontuarios/{prontuario_id}/verify")
async def verify_integrity(
    prontuario_id: str,
    request: Request,
    email: str = Depends(verify_doctor),
):
    """Verify the integrity hash of a prontuario to detect tampering. Doctor only."""
    oid = validate_object_id(prontuario_id, "Prontuário")
    doc = await db.prontuarios.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Prontuario not found")

    stored_hash = doc.get("integrity_hash", "")
    computed_hash = compute_integrity_hash(doc)
    is_valid = stored_hash == computed_hash

    await log_access(email, "VERIFY_INTEGRITY", prontuario_id,
                     f"valid={is_valid}", request)
    return {
        "success": True,
        "valid": is_valid,
        "integrity_valid": is_valid,
        "stored_hash": stored_hash,
        "computed_hash": computed_hash,
    }


@app.post("/prontuarios/{prontuario_id}/upload")
async def upload_anexo(
    prontuario_id: str,
    request: Request,
    file: UploadFile = File(...),
    descricao: str = Form(""),
    email: str = Depends(verify_doctor),
):
    """Upload an exam/file attachment to a prontuario. Doctor only. Max 10MB."""
    # Verify prontuario exists
    prontuario = await db.prontuarios.find_one({"_id": ObjectId(prontuario_id)})
    if not prontuario:
        raise HTTPException(status_code=404, detail="Prontuario not found")

    # Read file in chunks (max 10MB) to prevent memory exhaustion
    MAX_UPLOAD_SIZE = 10 * 1024 * 1024
    chunks = []
    total = 0
    while True:
        chunk = await file.read(8192)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
        chunks.append(chunk)
    content = b"".join(chunks)

    # Store file as base64 in anexos collection
    anexo_doc = {
        "prontuario_id": prontuario_id,
        "filename": file.filename or "arquivo",
        "content_type": file.content_type or "application/octet-stream",
        "size": len(content),
        "data": base64.b64encode(content).decode(),
        "descricao": descricao,
        "uploaded_by": email,
        "uploaded_at": datetime.now(timezone.utc),
    }
    result = await db.anexos.insert_one(anexo_doc)
    anexo_id = str(result.inserted_id)

    # Add reference to prontuario
    await db.prontuarios.update_one(
        {"_id": ObjectId(prontuario_id)},
        {
            "$push": {"anexos": {"id": anexo_id, "filename": file.filename, "descricao": descricao}},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )
    await log_access(email, "UPLOAD_ANEXO", prontuario_id, f"file={file.filename}, size={len(content)}", request)
    return {"success": True, "anexo_id": anexo_id, "filename": file.filename}


# --- Access Logs (Admin) ---

@app.get("/admin/access-logs")
async def admin_access_logs(
    limit: int = 100,
    user_email: Optional[str] = None,
    admin: bool = Depends(verify_admin),
):
    """View access logs for LGPD compliance. Admin only."""
    query = {}
    if user_email:
        query["user_email"] = user_email.strip().lower()
    docs = await db.access_logs.find(query).sort("timestamp", -1).to_list(length=limit)
    results = []
    for doc in docs:
        results.append({
            "user_email": doc.get("user_email", ""),
            "action": doc.get("action", ""),
            "prontuario_id": doc.get("prontuario_id", ""),
            "details": doc.get("details", ""),
            "ip": doc.get("ip", ""),
            "timestamp": doc["timestamp"].isoformat() if doc.get("timestamp") else None,
        })
    return {"success": True, "total": len(results), "logs": results}


# --- Confirmacao de Consulta (WhatsApp Link) ---

@app.post("/confirmacoes")
async def create_confirmacao(data: ConfirmacaoCreate, email: str = Depends(verify_token)):
    """Create a confirmation record for an appointment."""
    confirmation_uuid = str(uuid.uuid4())
    doc = {
        "uuid": confirmation_uuid,
        "appointment_id": data.appointment_id,
        "clinica_id": data.clinica_id,
        "patient_name": data.patient_name,
        "patient_whatsapp": data.patient_whatsapp,
        "appointment_date": data.appointment_date,
        "appointment_time": data.appointment_time,
        "doctor_name": data.doctor_name,
        "service": data.service,
        "status": "Pendente",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    await db.confirmacoes.insert_one(doc)
    return {"success": True, "uuid": confirmation_uuid, "status": "Pendente"}


@app.get("/confirmacoes/{clinica_id}")
async def list_confirmacoes(clinica_id: str, email: str = Depends(verify_token)):
    """List all confirmation records for a clinic."""
    docs = await db.confirmacoes.find({"clinica_id": clinica_id}).sort("created_at", -1).to_list(length=5000)
    results = []
    for doc in docs:
        results.append({
            "uuid": doc["uuid"],
            "appointment_id": doc.get("appointment_id", ""),
            "patient_name": doc.get("patient_name", ""),
            "patient_whatsapp": doc.get("patient_whatsapp", ""),
            "appointment_date": doc.get("appointment_date", ""),
            "appointment_time": doc.get("appointment_time", ""),
            "doctor_name": doc.get("doctor_name", ""),
            "service": doc.get("service", ""),
            "status": doc.get("status", "Pendente"),
            "updated_at": doc["updated_at"].isoformat() if doc.get("updated_at") else None,
        })
    return {"success": True, "data": results}


@app.patch("/confirmacoes/{confirmation_uuid}/enviar")
async def mark_confirmacao_enviado(confirmation_uuid: str, email: str = Depends(verify_token)):
    """Mark a confirmation as 'Enviado' (sent via WhatsApp)."""
    result = await db.confirmacoes.update_one(
        {"uuid": confirmation_uuid, "status": {"$nin": ["Confirmado", "Cancelado"]}},
        {"$set": {"status": "Enviado", "updated_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Confirmation not found")
    return {"success": True, "status": "Enviado"}


@app.get("/confirmar/{confirmation_uuid}", response_class=HTMLResponse)
async def confirmation_page(confirmation_uuid: str):
    """Public page for patient to confirm/cancel appointment."""
    doc = await db.confirmacoes.find_one({"uuid": confirmation_uuid})
    if not doc:
        return HTMLResponse(content=_confirmation_html_not_found(), status_code=404)

    status = doc.get("status", "Pendente")
    if status in ("Confirmado", "Cancelado"):
        return HTMLResponse(content=_confirmation_html_already_responded(
            doc.get("patient_name", ""),
            doc.get("doctor_name", ""),
            doc.get("appointment_date", ""),
            doc.get("appointment_time", ""),
            doc.get("service", ""),
            status,
        ))

    return HTMLResponse(content=_confirmation_html_form(
        confirmation_uuid,
        doc.get("patient_name", ""),
        doc.get("doctor_name", ""),
        doc.get("appointment_date", ""),
        doc.get("appointment_time", ""),
        doc.get("service", ""),
    ))


@app.post("/confirmar/{confirmation_uuid}/confirmar")
async def confirm_appointment(confirmation_uuid: str):
    """Public endpoint: patient confirms attendance."""
    result = await db.confirmacoes.update_one(
        {"uuid": confirmation_uuid, "status": {"$nin": ["Confirmado", "Cancelado"]}},
        {"$set": {"status": "Confirmado", "updated_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        doc = await db.confirmacoes.find_one({"uuid": confirmation_uuid})
        if not doc:
            raise HTTPException(status_code=404, detail="Not found")
        return HTMLResponse(content=_confirmation_html_already_responded(
            doc.get("patient_name", ""),
            doc.get("doctor_name", ""),
            doc.get("appointment_date", ""),
            doc.get("appointment_time", ""),
            doc.get("service", ""),
            doc.get("status", ""),
        ))
    doc = await db.confirmacoes.find_one({"uuid": confirmation_uuid})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return HTMLResponse(content=_confirmation_html_success(
        doc.get("patient_name", ""),
        doc.get("doctor_name", ""),
        doc.get("appointment_date", ""),
        doc.get("appointment_time", ""),
    ))


@app.post("/confirmar/{confirmation_uuid}/cancelar")
async def cancel_appointment(confirmation_uuid: str):
    """Public endpoint: patient cancels attendance."""
    result = await db.confirmacoes.update_one(
        {"uuid": confirmation_uuid, "status": {"$nin": ["Confirmado", "Cancelado"]}},
        {"$set": {"status": "Cancelado", "updated_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        doc = await db.confirmacoes.find_one({"uuid": confirmation_uuid})
        if not doc:
            raise HTTPException(status_code=404, detail="Not found")
        return HTMLResponse(content=_confirmation_html_already_responded(
            doc.get("patient_name", ""),
            doc.get("doctor_name", ""),
            doc.get("appointment_date", ""),
            doc.get("appointment_time", ""),
            doc.get("service", ""),
            doc.get("status", ""),
        ))
    doc = await db.confirmacoes.find_one({"uuid": confirmation_uuid})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return HTMLResponse(content=_confirmation_html_cancelled(
        doc.get("patient_name", ""),
        doc.get("doctor_name", ""),
        doc.get("appointment_date", ""),
        doc.get("appointment_time", ""),
    ))


# --- Confirmation HTML Templates ---

def _confirmation_base_css() -> str:
    return """
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body {
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: linear-gradient(135deg, #0a0a0f 0%, #101018 50%, #13131d 100%);
        min-height: 100vh; display: flex; align-items: center; justify-content: center;
        color: #fff; padding: 20px;
      }
      .card {
        background: #13131d; border: 1px solid rgba(212,175,55,0.2);
        border-radius: 16px; padding: 40px 32px; max-width: 480px; width: 100%;
        text-align: center; box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      }
      .logo { font-size: 28px; font-weight: 700; color: #d4af37; margin-bottom: 8px; }
      .subtitle { color: #8888a0; font-size: 14px; margin-bottom: 32px; }
      .patient-name { font-size: 22px; font-weight: 600; color: #fff; margin-bottom: 4px; }
      .doctor-name { color: #d4af37; font-size: 16px; margin-bottom: 24px; }
      .info-row {
        display: flex; align-items: center; justify-content: center; gap: 8px;
        color: #8888a0; font-size: 15px; margin-bottom: 8px;
      }
      .info-row svg { width: 18px; height: 18px; fill: #d4af37; }
      .divider { border: none; border-top: 1px solid rgba(255,255,255,0.06); margin: 24px 0; }
      .question { font-size: 18px; font-weight: 500; color: #fff; margin-bottom: 24px; }
      .btn-row { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
      .btn {
        padding: 14px 32px; border: none; border-radius: 10px; font-size: 16px;
        font-weight: 600; cursor: pointer; transition: all 0.2s; min-width: 160px;
      }
      .btn-confirm {
        background: linear-gradient(135deg, #45c97a, #2ea85e); color: #fff;
      }
      .btn-confirm:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(69,201,122,0.3); }
      .btn-cancel {
        background: linear-gradient(135deg, #e05577, #c03050); color: #fff;
      }
      .btn-cancel:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(224,85,119,0.3); }
      .status-icon { font-size: 64px; margin-bottom: 16px; }
      .status-msg { font-size: 18px; color: #fff; margin-bottom: 8px; font-weight: 500; }
      .status-sub { color: #8888a0; font-size: 14px; }
      form { display: inline; }
    </style>
    """


def _confirmation_html_form(uuid_str: str, patient: str, doctor: str, date: str, time: str, service: str) -> str:
    patient_safe = html_escape(patient)
    doctor_safe = html_escape(doctor)
    date_safe = html_escape(date)
    time_safe = html_escape(time)
    service_safe = html_escape(service)
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Confirmar Consulta - Medical Safe Gold</title>{_confirmation_base_css()}
</head><body>
<div class="card">
  <div class="logo">Medical Safe Gold</div>
  <div class="subtitle">Confirmacao de Consulta</div>
  <div class="patient-name">Ola, {patient_safe}!</div>
  <div class="doctor-name">Consulta com Dr(a). {doctor_safe}</div>
  <div class="info-row">
    <svg viewBox="0 0 24 24"><path d="M19 3h-1V1h-2v2H8V1H6v2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V8h14v11z"/></svg>
    <span>{date_safe}</span>
  </div>
  <div class="info-row">
    <svg viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>
    <span>{time_safe}</span>
  </div>
  <div class="info-row">
    <svg viewBox="0 0 24 24"><path d="M20 6h-4V4c0-1.1-.9-2-2-2h-4c-1.1 0-2 .9-2 2v2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-6 0h-4V4h4v2z"/></svg>
    <span>{service_safe}</span>
  </div>
  <hr class="divider">
  <div class="question">Confirma sua presenca?</div>
  <div class="btn-row">
    <form method="POST" action="/confirmar/{uuid_str}/confirmar">
      <button type="submit" class="btn btn-confirm">Sim, Confirmar</button>
    </form>
    <form method="POST" action="/confirmar/{uuid_str}/cancelar">
      <button type="submit" class="btn btn-cancel">Nao, Cancelar</button>
    </form>
  </div>
</div>
</body></html>"""


def _confirmation_html_success(patient: str, doctor: str, date: str, time: str) -> str:
    patient_safe = html_escape(patient)
    doctor_safe = html_escape(doctor)
    date_safe = html_escape(date)
    time_safe = html_escape(time)
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Consulta Confirmada - Medical Safe Gold</title>{_confirmation_base_css()}
</head><body>
<div class="card">
  <div class="logo">Medical Safe Gold</div>
  <div class="status-icon" style="color:#45c97a;">&#10003;</div>
  <div class="status-msg">Consulta Confirmada!</div>
  <div class="status-sub">{patient_safe}, sua consulta com Dr(a). {doctor_safe} em {date_safe} as {time_safe} foi confirmada com sucesso.</div>
  <hr class="divider">
  <div class="status-sub">Obrigado! Nos vemos em breve.</div>
</div>
</body></html>"""


def _confirmation_html_cancelled(patient: str, doctor: str, date: str, time: str) -> str:
    patient_safe = html_escape(patient)
    doctor_safe = html_escape(doctor)
    date_safe = html_escape(date)
    time_safe = html_escape(time)
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Consulta Cancelada - Medical Safe Gold</title>{_confirmation_base_css()}
</head><body>
<div class="card">
  <div class="logo">Medical Safe Gold</div>
  <div class="status-icon" style="color:#e05577;">&#10007;</div>
  <div class="status-msg">Consulta Cancelada</div>
  <div class="status-sub">{patient_safe}, sua consulta com Dr(a). {doctor_safe} em {date_safe} as {time_safe} foi cancelada.</div>
  <hr class="divider">
  <div class="status-sub">Se precisar reagendar, entre em contato com a clinica.</div>
</div>
</body></html>"""


def _confirmation_html_already_responded(patient: str, doctor: str, date: str, time: str, service: str, status: str) -> str:
    patient_safe = html_escape(patient)
    doctor_safe = html_escape(doctor)
    date_safe = html_escape(date)
    time_safe = html_escape(time)
    if status == "Confirmado":
        icon = '<div class="status-icon" style="color:#45c97a;">&#10003;</div>'
        msg = "Consulta ja Confirmada"
        sub = f"{patient_safe}, sua consulta com Dr(a). {doctor_safe} em {date_safe} as {time_safe} ja foi confirmada anteriormente."
    else:
        icon = '<div class="status-icon" style="color:#e05577;">&#10007;</div>'
        msg = "Consulta ja Cancelada"
        sub = f"{patient_safe}, sua consulta com Dr(a). {doctor_safe} em {date_safe} as {time_safe} ja foi cancelada anteriormente."
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{msg} - Medical Safe Gold</title>{_confirmation_base_css()}
</head><body>
<div class="card">
  <div class="logo">Medical Safe Gold</div>
  {icon}
  <div class="status-msg">{msg}</div>
  <div class="status-sub">{sub}</div>
  <hr class="divider">
  <div class="status-sub">Se precisar de algo, entre em contato com a clinica.</div>
</div>
</body></html>"""


def _confirmation_html_not_found() -> str:
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nao Encontrado - Medical Safe Gold</title>{_confirmation_base_css()}
</head><body>
<div class="card">
  <div class="logo">Medical Safe Gold</div>
  <div class="status-icon" style="color:#8888a0;">?</div>
  <div class="status-msg">Link Invalido</div>
  <div class="status-sub">Este link de confirmacao nao foi encontrado ou expirou.</div>
</div>
</body></html>"""
