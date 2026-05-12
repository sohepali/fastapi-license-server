import os
import re
import smtplib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from jose import jwt
from dotenv import load_dotenv
from email.mime.text import MIMEText

from slowapi import Limiter
from slowapi.util import get_remote_address

from passlib.context import CryptContext
import hashlib
from fastapi import Request


def create_device_fingerprint(device_id: str, request: Request) -> str:
    raw = f"{device_id}"
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return fingerprint


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
BASE_URL = os.getenv("BASE_URL")
print("SMTP_SERVER =", SMTP_SERVER)
print("SMTP_PORT =", SMTP_PORT)
print("SMTP_USER =", SMTP_USER)
print("SMTP_PASSWORD exists =", SMTP_PASSWORD is not None)
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "RS256"

TRIAL_DAYS = 3
APP_NAME = "SAMA AI"
APP_VERSION = "2.0.0"
APP_BUILD_DATE = "May 2026"
APP_WEBSITE_URL = os.getenv("APP_WEBSITE_URL", "https://samaail.netlify.app/")
APP_DOWNLOAD_URL = os.getenv(
    "APP_DOWNLOAD_URL",
    "https://69fc831415505220d12439eb--profound-sfogliatella-81eec2.netlify.app/#download",
)
PAYMENT_URL = os.getenv(
    "PAYMENT_URL",
    "https://samaai.lemonsqueezy.com/checkout/buy/4e1e15f2-b41c-4631-8457-af7aadb738d0",
)
PAYMENT_PLANS = {
    "day": {"amount_usd": 2, "days": 1},
    "week": {"amount_usd": 10, "days": 7},
    "month": {"amount_usd": 30, "days": 30},
}

engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[BASE_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------
# DATABASE MODEL
# ------------------------------

class User(Base):
    __tablename__ = "users"

    email = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=True)
    password = Column(String)

    email_verified = Column(Boolean, default=False)

    verification_code = Column(String, nullable=True)

    refresh_token = Column(String, nullable=True)

    subscription_expiry = Column(DateTime, nullable=True)
    device_id = Column(String, nullable=True)
    account_type = Column(String, default="free")
    payment_status = Column(String, default="trial")
    last_payment_amount = Column(String, nullable=True)
    last_payment_currency = Column(String, nullable=True)
    last_payment_provider = Column(String, nullable=True)
    last_payment_id = Column(String, nullable=True)
    last_payment_date = Column(DateTime, nullable=True)
    last_app_version = Column(String, nullable=True)
    last_app_build_date = Column(String, nullable=True)
    last_website_url = Column(String, nullable=True)
    last_download_url = Column(String, nullable=True)
    last_payment_url = Column(String, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    last_update_required = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)


def ensure_user_profile_columns():
    """Add profile/billing/update columns without requiring a manual DB reset."""
    existing = {col["name"] for col in inspect(engine).get_columns("users")}
    columns = {
        "name": "VARCHAR",
        "account_type": "VARCHAR DEFAULT 'free'",
        "payment_status": "VARCHAR DEFAULT 'trial'",
        "last_payment_amount": "VARCHAR",
        "last_payment_currency": "VARCHAR",
        "last_payment_provider": "VARCHAR",
        "last_payment_id": "VARCHAR",
        "last_payment_date": "TIMESTAMP",
        "last_app_version": "VARCHAR",
        "last_app_build_date": "VARCHAR",
        "last_website_url": "VARCHAR",
        "last_download_url": "VARCHAR",
        "last_payment_url": "VARCHAR",
        "last_seen_at": "TIMESTAMP",
        "last_update_required": "BOOLEAN DEFAULT false",
    }
    with engine.begin() as conn:
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))


ensure_user_profile_columns()


# ------------------------------
# Pydantic Models
# ------------------------------
def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    device_id: str

class VerifyRequest(BaseModel):
    email: EmailStr
    code: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_id: str
    app_name: Optional[str] = None
    app_version: Optional[str] = None
    app_build_date: Optional[str] = None
    platform: Optional[str] = None


class LicenseCheckRequest(BaseModel):
    app_name: Optional[str] = None
    app_version: Optional[str] = None
    app_build_date: Optional[str] = None
    platform: Optional[str] = None

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

class RefreshRequest(BaseModel):
    refresh_token: str


# ------------------------------
# DB Dependency
# ------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------
# Email sender
# ------------------------------

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os

def _send_email(to_email: str, subject: str, html_content: str) -> None:
    errors = []
    sendgrid_key = (os.getenv("SENDGRID_API_KEY") or "").strip()

    if sendgrid_key:
        try:
            message = Mail(
                from_email=os.getenv("SMTP_USER") or "sama.ai.license@gmail.com",
                to_emails=to_email,
                subject=subject,
                html_content=html_content,
            )
            sg = SendGridAPIClient(sendgrid_key)
            response = sg.send(message)
            print("SENDGRID STATUS:", response.status_code)
            return
        except Exception as e:
            errors.append(f"SendGrid failed: {e}")
            print("SENDGRID ERROR:", e)

    try:
        if not all([SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD]):
            raise RuntimeError("SMTP settings are incomplete")

        msg = MIMEText(html_content, "html")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = to_email

        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        print("SMTP EMAIL SENT")
        return
    except Exception as e:
        errors.append(f"SMTP failed: {e}")
        print("SMTP ERROR:", e)

    raise RuntimeError("; ".join(errors) or "Email sending failed")


def send_verification_email(email, code):
    _send_email(
        email,
        "Email Verification",
        f"<strong>Your verification code is: {code}</strong>",
    )

def send_password_reset_email(email, code):
    _send_email(
        email,
        "SAMA AI Password Reset",
        (
            "<p>Your SAMA AI username is your registered email address:</p>"
            f"<p><strong>{email}</strong></p>"
            "<p>Use this code to reset your password:</p>"
            f"<h2>{code}</h2>"
            "<p>If you did not request this, you can ignore this email.</p>"
        ),
    )
# ------------------------------
# App/account policy helpers
# ------------------------------

def _version_tuple(value: Optional[str]) -> tuple:
    if not value:
        return tuple()
    numbers = [int(part) for part in re.findall(r"\d+", str(value))]
    return tuple(numbers or [0])


def _version_less_than(left: Optional[str], right: Optional[str]) -> bool:
    left_parts = list(_version_tuple(left))
    right_parts = list(_version_tuple(right))
    size = max(len(left_parts), len(right_parts), 1)
    left_parts += [0] * (size - len(left_parts))
    right_parts += [0] * (size - len(right_parts))
    return tuple(left_parts) < tuple(right_parts)


def build_update_policy(client_version: Optional[str]) -> dict:
    latest = os.getenv("APP_LATEST_VERSION", APP_VERSION)
    minimum = os.getenv("APP_MIN_SUPPORTED_VERSION", APP_VERSION)
    force_update = os.getenv("APP_FORCE_UPDATE", "").strip().lower() in {"1", "true", "yes", "y"}
    known_client = bool(client_version)
    update_available = known_client and _version_less_than(client_version, latest)
    update_required = force_update or (known_client and _version_less_than(client_version, minimum))
    return {
        "app_name": APP_NAME,
        "client_version": client_version or "",
        "latest_version": latest,
        "minimum_supported_version": minimum,
        "app_build_date": APP_BUILD_DATE,
        "website_url": APP_WEBSITE_URL,
        "download_url": APP_DOWNLOAD_URL,
        "update_available": bool(update_available or update_required),
        "update_required": bool(update_required),
    }


def build_payment_policy() -> dict:
    return {
        "payment_url": PAYMENT_URL,
        "provider": "lemonsqueezy",
        "plans": PAYMENT_PLANS,
    }


def days_left(expiry: Optional[datetime]) -> int:
    if not expiry:
        return 0
    remaining = expiry - datetime.utcnow()
    if remaining.total_seconds() <= 0:
        return 0
    return max(1, remaining.days + 1)


def normalize_account_fields(user: User) -> None:
    active = bool(user.subscription_expiry and user.subscription_expiry > datetime.utcnow())
    if not user.account_type:
        user.account_type = "paid" if user.last_payment_amount else "free"
    if not user.payment_status:
        user.payment_status = "active" if active else "expired"
    if user.last_payment_amount and active:
        user.account_type = "paid"
        user.payment_status = "active"
    elif not active and user.email_verified:
        user.payment_status = "expired"


def build_account_status(user: User) -> dict:
    normalize_account_fields(user)
    active = bool(user.subscription_expiry and user.subscription_expiry > datetime.utcnow())
    return {
        "email": user.email,
        "email_verified": bool(user.email_verified),
        "account_type": user.account_type or "free",
        "payment_status": user.payment_status or ("active" if active else "expired"),
        "is_paid": bool((user.account_type == "paid") and active),
        "license_active": active,
        "subscription_expiry": user.subscription_expiry.isoformat() if user.subscription_expiry else None,
        "days_left": days_left(user.subscription_expiry),
        "last_payment_amount": user.last_payment_amount,
        "last_payment_currency": user.last_payment_currency,
        "last_payment_provider": user.last_payment_provider,
        "last_payment_date": user.last_payment_date.isoformat() if user.last_payment_date else None,
        "last_app_version": user.last_app_version,
        "last_app_build_date": user.last_app_build_date,
        "last_website_url": user.last_website_url,
        "last_download_url": user.last_download_url,
        "last_payment_url": user.last_payment_url,
        "last_update_required": bool(user.last_update_required),
    }


def record_client_state(user: User, client: Optional[LicenseCheckRequest | LoginRequest]) -> dict:
    app_version = getattr(client, "app_version", None) if client else None
    app_build_date = getattr(client, "app_build_date", None) if client else None
    policy = build_update_policy(app_version)
    user.last_app_version = app_version or user.last_app_version
    user.last_app_build_date = app_build_date or user.last_app_build_date
    user.last_website_url = APP_WEBSITE_URL
    user.last_download_url = APP_DOWNLOAD_URL
    user.last_payment_url = PAYMENT_URL
    user.last_seen_at = datetime.utcnow()
    user.last_update_required = bool(policy["update_required"])
    return policy


def build_server_state(user: User, update_policy: dict) -> dict:
    return {
        "account_status": build_account_status(user),
        "update_policy": update_policy,
        "payment_policy": build_payment_policy(),
    }


# ------------------------------
# JWT
# ------------------------------

def create_access_token(
    email: str,
    expiry: datetime,
    device_id: Optional[str] = None,
    account_type: str = "free",
    payment_status: str = "trial",
) -> str:
    payload = {
        "sub": email,
        "email": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=12),
        "iss": "SAMA_AI",
        "expiry": expiry.isoformat(),
        "device_id": device_id,
        "account_type": account_type,
        "payment_status": payment_status,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token():

    return secrets.token_hex(32)


# ------------------------------
# SERVER STATUS
# ------------------------------

@app.get("/")
def root():

    return {
        "status": "server running",
        "app_name": APP_NAME,
        "latest_version": os.getenv("APP_LATEST_VERSION", APP_VERSION),
        "minimum_supported_version": os.getenv("APP_MIN_SUPPORTED_VERSION", APP_VERSION),
        "download_url": APP_DOWNLOAD_URL,
        "payment_url": PAYMENT_URL,
        "timestamp": datetime.utcnow().timestamp()
    }

# ------------------------------
# REGISTER
# ------------------------------

from fastapi import Request

@app.post("/register")
@limiter.limit("3/minute")
def register(request: Request, data: RegisterRequest, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()
    if user and user.email_verified:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    if user:
        if not user.email_verified:
            if data.name:
                user.name = data.name
            if data.password:
                user.password = hash_password(data.password)
            db.commit()
            try:
                send_verification_email(user.email, user.verification_code)
            except Exception as e:
                print("EMAIL ERROR:", e)
                raise HTTPException(
                    status_code=503,
                    detail="Account exists, but verification email could not be sent. Please check server email settings.",
                )
            return {"message": "verification code resent"}
        return {"message": "email already registered, please login"}

    code = str(secrets.randbelow(900000) + 100000)

    new_user = User(
        email=data.email,
        name=data.name,
        password=hash_password(data.password),
        verification_code=code,
        email_verified=False,
        device_id=None,
        account_type="free",
        payment_status="trial",
    )
    db.add(new_user)
    db.commit()

    try:
        send_verification_email(data.email, code)
    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(
            status_code=503,
            detail="Account was created, but verification email could not be sent. Please check server email settings.",
        )

    return {"message": "verification code sent"}
# ------------------------------
# VERIFY EMAIL
# ------------------------------

@app.post("/verify_email")
def verify_email(data: VerifyRequest, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.email_verified:
        return {"message": "email already verified"}

    if user.verification_code != data.code:
        raise HTTPException(status_code=400, detail="Invalid code")

    user.email_verified = True
    user.verification_code = None
    user.subscription_expiry = datetime.utcnow() + timedelta(days=TRIAL_DAYS)
    user.account_type = "free"
    user.payment_status = "trial"

    db.commit()

    return {"message": "email verified"}

# ------------------------------
# PASSWORD RESET
# ------------------------------

@app.post("/forgot_password")
@limiter.limit("3/minute")
def forgot_password(
    request: Request,
    data: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):

    generic_message = {
        "message": "If this email is registered, a password reset code was sent."
    }

    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        return generic_message

    code = str(secrets.randbelow(900000) + 100000)
    user.verification_code = f"reset:{code}"
    db.commit()

    try:
        send_password_reset_email(user.email, code)
    except Exception as e:
        print("PASSWORD RESET EMAIL ERROR:", e)
        raise HTTPException(status_code=500, detail="Could not send reset email")

    return generic_message


@app.post("/reset_password")
@limiter.limit("5/minute")
def reset_password(
    request: Request,
    data: ResetPasswordRequest,
    db: Session = Depends(get_db)
):

    if len(data.new_password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password too long")

    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset code")

    expected_code = f"reset:{data.code}"
    if user.verification_code != expected_code:
        raise HTTPException(status_code=400, detail="Invalid reset code")

    user.password = hash_password(data.new_password)
    user.verification_code = None
    db.commit()

    return {"message": "Password updated. Please log in with your new password."}

# ------------------------------
# LOGIN
# ------------------------------

from fastapi import Request

@app.post("/login")
@limiter.limit("5/minute")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    update_policy = record_client_state(user, data)
    normalize_account_fields(user)

    if user.subscription_expiry and datetime.utcnow() > user.subscription_expiry:
        db.commit()
        raise HTTPException(
            status_code=402,
            detail={
                "message": "Subscription expired",
                "account_status": build_account_status(user),
                "payment_policy": build_payment_policy(),
                "update_policy": update_policy,
            },
        )

    # -------------------------
    # DEVICE FINGERPRINT CHECK
    # -------------------------
    fingerprint = create_device_fingerprint(data.device_id, request)

    if user.device_id is None:
        user.device_id = fingerprint
    elif user.device_id != fingerprint:
        raise HTTPException(
            status_code=403,
            detail="Account already used on another device"
        )

    # -------------------------
    # TOKEN CREATION
    # -------------------------
    access_token = create_access_token(
        user.email,
        user.subscription_expiry,
        device_id=data.device_id,
        account_type=user.account_type or "free",
        payment_status=user.payment_status or "active",
    )
    refresh_token = create_refresh_token()
    user.refresh_token = refresh_token

    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        **build_server_state(user, update_policy),
    }




from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

@app.post("/check_license")
def check_license(
    data: Optional[LicenseCheckRequest] = None,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):

    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer="SAMA_AI"
        )
        email = payload["sub"]
        token_device_id = payload.get("device_id")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_policy = record_client_state(user, data)
    normalize_account_fields(user)

    if user.subscription_expiry and datetime.utcnow() > user.subscription_expiry:
        db.commit()
        raise HTTPException(
            status_code=402,
            detail={
                "message": "Subscription expired",
                "account_status": build_account_status(user),
                "payment_policy": build_payment_policy(),
                "update_policy": update_policy,
            },
        )

    new_token = create_access_token(
        user.email,
        user.subscription_expiry,
        device_id=token_device_id,
        account_type=user.account_type or "free",
        payment_status=user.payment_status or "active",
    )

    db.commit()

    return {"token": new_token, **build_server_state(user, update_policy)}
# ------------------------------
# REFRESH TOKEN
# ------------------------------

@app.post("/refresh")
def refresh(data: RefreshRequest, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.refresh_token == data.refresh_token).first()
    user = db.query(User).filter(
        User.refresh_token == data.refresh_token
    ).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if datetime.utcnow() > user.subscription_expiry:

        raise HTTPException(
            status_code=402,
            detail="Subscription expired"
        )

    access_token = create_access_token(user.email, user.subscription_expiry)

    return {"access_token": access_token}


# ------------------------------
# ACCOUNT STATUS
# ------------------------------

@app.get("/account_status/{email}")
def account_status(email: str, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    normalize_account_fields(user)
    active = bool(user.subscription_expiry and user.subscription_expiry > datetime.utcnow())

    return {
        "email_verified": user.email_verified,
        "trial_active": active and user.account_type != "paid",
        "days_left": days_left(user.subscription_expiry),
        "account_status": build_account_status(user),
        "payment_policy": build_payment_policy(),
        "update_policy": build_update_policy(user.last_app_version),
    }



@app.post("/renew/{email}")
@limiter.limit("5/minute")
def renew_subscription(
    request: Request,
    email: str,
    x_admin_token: str = Header(default=""),
    db: Session = Depends(get_db),
):

    expected_token = os.getenv("ADMIN_RENEW_TOKEN")

    if not expected_token or x_admin_token != expected_token:
        raise HTTPException(status_code=403, detail="Admin renewal is not authorized")

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.subscription_expiry = datetime.utcnow() + timedelta(days=30)
    user.account_type = "paid"
    user.payment_status = "active"

    db.commit()

    return {"message": "subscription renewed", "account_status": build_account_status(user)}


# ------------------------------
# STRIPE PAYMENT AUTOMATION
# ------------------------------

try:
    from payment_automation import create_payment_router

    app.include_router(create_payment_router(User, get_db))
except Exception as e:
    print("PAYMENT AUTOMATION DISABLED:", e)
