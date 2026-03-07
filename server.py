from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, String, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt
import os
from dotenv import load_dotenv
from sqlalchemy import Text
import secrets
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict
import time

login_attempts = defaultdict(list)
# =========================
# LOAD ENVIRONMENT VARIABLES
# =========================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")   # Will contain the RSA private key with \n for newlines
PUBLIC_KEY = os.getenv("PUBLIC_KEY")

if not PUBLIC_KEY:
    raise ValueError("PUBLIC_KEY not found in .env file")

PUBLIC_KEY = PUBLIC_KEY.replace("\\n", "\n")


if not DATABASE_URL:
    raise ValueError("DATABASE_URL not found in .env file")
if not PRIVATE_KEY:
    raise ValueError("PRIVATE_KEY not found in .env file")

# Handle newlines in environment variable
PRIVATE_KEY = PRIVATE_KEY.replace("\\n", "\n")

ALGORITHM = "RS256"


# =========================
# DATABASE SETUP
# =========================
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =========================
# PASSWORD HASHING SETUP
# =========================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def hash_token(token: str):
    return pwd_context.hash(token)

def verify_token(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def send_verification_email(to_email: str, token: str):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    base_url = os.getenv("BASE_URL")

    verification_link = f"{base_url}/verify?token={token}"

    subject = "Verify Your Account"
    body = f"""
    Click the link below to verify your account:

    {verification_link}

    This link expires in 15 minutes.
    """

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)




def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# =========================
# FASTAPI INSTANCE
# =========================
app = FastAPI()

# =========================
# DATABASE MODEL
# =========================
class User(Base):
    __tablename__ = "users"

    email = Column(String(255), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    device_id = Column(String(255), nullable=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(255), nullable=True)
    verification_expiry = Column(DateTime, nullable=True)
    refresh_token = Column(String(255), nullable=True)
    refresh_expiry = Column(DateTime, nullable=True)

    trial_start = Column(DateTime, default=datetime.utcnow)
    
    subscription_type = Column(String, default="trial")  # trial / premium
    subscription_expiry = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)


# Create tables (optional - better to run migrations separately)
Base.metadata.create_all(bind=engine)

# =========================
# REQUEST MODELS
# =========================
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    device_id: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_id: str

class VerifyRequest(BaseModel):
    email: EmailStr
    token: str
class RefreshRequest(BaseModel):
    refresh_token: str
    device_id: str
# =========================
# DEPENDENCY: GET DB SESSION
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# REGISTER ENDPOINT
# =========================
@app.post("/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    try:
        hashed_pw = hash_password(data.password)
    except ValueError as e:
        # This catches bcrypt's "password too long" and other hashing errors
        raise HTTPException(status_code=400, detail=str(e))

    trial_start = datetime.utcnow()
    expiry_date = trial_start + timedelta(days=3)
    verification_token = secrets.token_urlsafe(32)
    verification_expiry = datetime.utcnow() + timedelta(minutes=15)
    new_user = User(
        email=data.email,
        name=data.name,
        password=hashed_pw,
        is_verified=False,
        trial_start=trial_start,
        subscription_type="trial",
        subscription_expiry=expiry_date,
        device_id=None,
        verification_token=verification_token,
        verification_expiry=verification_expiry
    )

    db.add(new_user)
    db.commit()
    send_verification_email(data.email, verification_token)

    return {
        "message": "User registered successfully. Check your email to verify."
    }
# =========================
# LOGIN ENDPOINT
# =========================
@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    current_time = time.time()
    key = f"{data.email}:{data.device_id}"
    attempts = login_attempts[key]

    login_attempts[key] = [t for t in attempts if current_time - t < 300]

    if len(login_attempts[key]) >= 5:
        raise HTTPException(status_code=429, detail="Too many login attempts")

    login_attempts[key].append(current_time)
    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 🔒 Account disabled check (STEP 3)
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    # Device binding
    if not user.device_id:
        user.device_id = data.device_id
        db.commit()
    elif user.device_id != data.device_id:
        raise HTTPException(status_code=403, detail="Device mismatch")

    if datetime.utcnow() > user.subscription_expiry:
        raise HTTPException(status_code=403, detail="License expired")

    payload = {
        "sub": user.email,
        "email": user.email,
        "device_id": user.device_id,
        "expiry": user.subscription_expiry.isoformat(),
        "type": "access",
        "exp": datetime.utcnow() + timedelta(days=7)
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)

    # 🔒 Refresh token with expiry (STEP 2)
    refresh_token = create_refresh_token()
    user.refresh_token = hash_token(refresh_token)
    user.refresh_expiry = datetime.utcnow() + timedelta(days=7)

    db.commit()
    login_attempts[key] = []

    return {
        "access_token": token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@app.post("/refresh")
def refresh_access_token(data: RefreshRequest, db: Session = Depends(get_db)):

    if not data.device_id:
        raise HTTPException(status_code=400, detail="Device ID required")

    users = db.query(User).all()

    user = None
    for u in users:
        if u.refresh_token and verify_token(data.refresh_token, u.refresh_token):
            user = u
            break

    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # 🔒 Account disabled check
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    # 🔒 Refresh expiry check (STEP 2)
    if not user.refresh_expiry or datetime.utcnow() > user.refresh_expiry:
        raise HTTPException(status_code=403, detail="Refresh token expired")

    # Device validation
    if not user.device_id:
        raise HTTPException(status_code=403, detail="Device not registered")

    if user.device_id != data.device_id:
        raise HTTPException(status_code=403, detail="Device mismatch")

    if datetime.utcnow() > user.subscription_expiry:
        raise HTTPException(status_code=403, detail="License expired")

    # Issue new access token
    payload = {
        "sub": user.email,
        "email": user.email,
        "device_id": user.device_id,
        "expiry": user.subscription_expiry.isoformat(),
        "type": "access",
        "exp": user.subscription_expiry
    }

    new_access_token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)

    # 🔁 Refresh rotation
    new_refresh_token = create_refresh_token()
    user.refresh_token = hash_token(new_refresh_token)
    user.refresh_expiry = datetime.utcnow() + timedelta(days=7)

    db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }




def create_refresh_token():
    return secrets.token_urlsafe(40)



@app.get("/db_check")
def db_check(db: Session = Depends(get_db)):
    try:
        count = db.query(User).count()
        return {"status": "ok", "user_count": count}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
# =========================
# VERIFY ENDPOINT (simple email verification, no code check)
# =========================
from fastapi import Query

@app.get("/verify")
def verify_user(token: str = Query(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verification_token == token).first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    if datetime.utcnow() > user.verification_expiry:
        raise HTTPException(status_code=400, detail="Token expired")

    user.is_verified = True
    user.verification_token = None
    user.verification_expiry = None
    db.commit()

    return {"message": "Account verified successfully"}


# =========================
# CHECK LICENSE ENDPOINT
# =========================
@app.post("/check_license")
def check_license(authorization: str = Header(...), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]

    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])

        # 🔐 ADD THIS HERE
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        email = payload.get("sub")
        token_device_id = payload.get("device_id")
        if not email or not token_device_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")



    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    


    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if user.device_id != token_device_id:
     raise HTTPException(status_code=403, detail="Device mismatch")

    if datetime.utcnow() > user.subscription_expiry:
        raise HTTPException(status_code=403, detail="License expired")

    # Issue a new token with updated expiry (in case it was extended)
    new_payload = {
        "sub": user.email,
        "email": user.email,
        "device_id": user.device_id,
        "expiry": user.subscription_expiry.isoformat(),
        "type": "access",
        "exp": user.subscription_expiry
    }
    new_token = jwt.encode(new_payload, PRIVATE_KEY, algorithm=ALGORITHM)
    

    return {
        "status": "active",
        "token": new_token
    }

# =========================
# TIME ENDPOINT (optional, for trusted time fallback)
# =========================
@app.get("/time")
def get_time():
    return {"timestamp": datetime.utcnow().timestamp()}


class UpgradeRequest(BaseModel):
    email: EmailStr
    admin_key: str


@app.post("/upgrade_to_premium")
def upgrade_to_premium(data: UpgradeRequest, db: Session = Depends(get_db)):
    if data.admin_key != os.getenv("ADMIN_VERIFY_KEY"):
        raise HTTPException(status_code=403, detail="Invalid admin key")

    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.subscription_type = "premium"
    user.subscription_expiry = datetime.utcnow() + timedelta(days=30)

    db.commit()

    return {"message": "User upgraded to premium"}


@app.get("/admin_stats")
def admin_stats(admin_key: str, db: Session = Depends(get_db)):
    if admin_key != os.getenv("ADMIN_VERIFY_KEY"):
        raise HTTPException(status_code=403, detail="Unauthorized")

    total_users = db.query(User).count()
    trial_users = db.query(User).filter(User.subscription_type == "trial").count()
    premium_users = db.query(User).filter(User.subscription_type == "premium").count()
    expired_users = db.query(User).filter(User.subscription_expiry < datetime.utcnow()).count()

    return {
        "total_users": total_users,
        "trial_users": trial_users,
        "premium_users": premium_users,
        "expired_users": expired_users
    }
