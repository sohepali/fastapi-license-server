from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, String, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt
import os
from dotenv import load_dotenv

# =========================
# LOAD ENVIRONMENT VARIABLES
# =========================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")   # Will contain the RSA private key with \n for newlines

if not DATABASE_URL:
    raise ValueError("DATABASE_URL not found in .env file")
if not PRIVATE_KEY:
    raise ValueError("PRIVATE_KEY not found in .env file")

# Handle newlines in environment variable
PRIVATE_KEY = PRIVATE_KEY.replace("\\n", "\n")

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

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

    email = Column(String, primary_key=True, index=True)
    name = Column(String)
    password = Column(String)

    is_verified = Column(Boolean, default=False)

    trial_start = Column(DateTime, default=datetime.utcnow)
    subscription_type = Column(String, default="trial")  # trial / premium
    subscription_expiry = Column(DateTime)

    device_id = Column(String, nullable=True)

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

    trial_start = datetime.utcnow()
    expiry_date = trial_start + timedelta(days=3)

    hashed_pw = hash_password(data.password)

    new_user = User(
        email=data.email,
        name=data.name,
        password=hashed_pw,
        is_verified=False,
        trial_start=trial_start,
        subscription_type="trial",
        subscription_expiry=expiry_date,
        device_id=data.device_id
    )

    db.add(new_user)
    db.commit()

    return {
        "message": "User registered successfully",
        "subscription_type": "trial",
        "expires_on": expiry_date.isoformat()
    }

# =========================
# LOGIN ENDPOINT
# =========================
@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if datetime.utcnow() > user.subscription_expiry:
        raise HTTPException(status_code=403, detail="License expired")

    # Create JWT payload
    payload = {
        "email": user.email,
        "device_id": user.device_id,
        "expiry": user.subscription_expiry.isoformat(),
        "exp": datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# =========================
# VERIFY ENDPOINT (simple email verification, no code check)
# =========================
@app.post("/verify")
def verify_user(data: VerifyRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_verified = True
    db.commit()
    return {"status": "success", "message": "User verified successfully"}

# =========================
# CHECK LICENSE ENDPOINT
# =========================
@app.post("/check_license")
def check_license(authorization: str = Header(...), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]

    try:
        payload = jwt.decode(token, PRIVATE_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if datetime.utcnow() > user.subscription_expiry:
        raise HTTPException(status_code=403, detail="License expired")

    # Issue a new token with updated expiry (in case it was extended)
    new_payload = {
        "email": user.email,
        "device_id": user.device_id,
        "expiry": user.subscription_expiry.isoformat(),
        "exp": datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    }
    new_token = jwt.encode(new_payload, PRIVATE_KEY, algorithm=ALGORITHM)

    return {"token": new_token}

# =========================
# TIME ENDPOINT (optional, for trusted time fallback)
# =========================
@app.get("/time")
def get_time():
    return {"timestamp": datetime.utcnow().timestamp()}