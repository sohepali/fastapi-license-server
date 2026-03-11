import os
import smtplib
import secrets
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, String, Boolean, DateTime
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
    """
    Generates a device fingerprint based on device_id, client IP, and user-agent.
    """
    user_agent = request.headers.get("user-agent", "")
    client_ip = request.client.host if request.client else ""
    raw = f"{device_id}:{user_agent}"
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
    password = Column(String)

    email_verified = Column(Boolean, default=False)

    verification_code = Column(String, nullable=True)

    refresh_token = Column(String, nullable=True)

    subscription_expiry = Column(DateTime, nullable=True)
    device_id = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)


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

def send_verification_email(email, code):

    try:
        message = Mail(
            from_email="sama.ai.license@gmail.com",
            to_emails=email,
            subject="Email Verification",
            html_content=f"<strong>Your verification code is: {code}</strong>"
        )

        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sg.send(message)

        print("SENDGRID STATUS:", response.status_code)

    except Exception as e:
        print("SENDGRID ERROR:", e)
        raise e
# ------------------------------
# JWT
# ------------------------------

def create_access_token(email):

    payload = {
        "sub": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=12),
        "iss": "SAMA_AI"
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
            send_verification_email(user.email, user.verification_code)
            return {"message": "verification code resent"}
        return {"message": "email already registered, please login"}

    code = str(secrets.randbelow(900000) + 100000)

    try:
        send_verification_email(data.email, code)
    except Exception as e:
        print("EMAIL ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))

    new_user = User(
        email=data.email,
        password=hash_password(data.password),
        verification_code=code,
        email_verified=False,
        device_id=None
    )
    db.add(new_user)
    db.commit()

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

    db.commit()

    return {"message": "email verified"}

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

    if user.subscription_expiry and datetime.utcnow() > user.subscription_expiry:
        raise HTTPException(status_code=402, detail="Subscription expired")

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
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token()
    user.refresh_token = refresh_token

    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }




from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

@app.post("/check_license")
def check_license(
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
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.subscription_expiry and datetime.utcnow() > user.subscription_expiry:
        raise HTTPException(status_code=402, detail="Subscription expired")

    # إصدار token جديد
    new_token = create_access_token(user.email)

    return {"token": new_token}
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

    access_token = create_access_token(user.email)

    return {"access_token": access_token}


# ------------------------------
# ACCOUNT STATUS
# ------------------------------

@app.get("/account_status/{email}")
def account_status(email: str, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    trial_active = False
    days_left = 0

    if user.subscription_expiry:

        remaining = user.subscription_expiry - datetime.utcnow()

        if remaining.total_seconds() > 0:
            trial_active = True
            days_left = remaining.days

    return {
        "email_verified": user.email_verified,
        "trial_active": trial_active,
        "days_left": days_left
    }



@app.post("/renew/{email}")
@limiter.limit("5/minute")
def renew_subscription(request: Request, email: str, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.subscription_expiry = datetime.utcnow() + timedelta(days=30)

    db.commit()

    return {"message": "subscription renewed"}