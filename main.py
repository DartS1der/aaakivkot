from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, Dict
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import json

# === CONFIG ===
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "sqlite:///./iot.db"

# === SETUP ===
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# === MODELS ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    device = relationship("Device", uselist=False, back_populates="owner")

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    settings = Column(Text, default='{}')
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="device")

Base.metadata.create_all(bind=engine)

# === SCHEMAS ===
class RegisterModel(BaseModel):
    email: str
    password: str

class SettingsModel(BaseModel):
    settings: Dict

class Token(BaseModel):
    access_token: str
    token_type: str

# === UTILS ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# === ROUTES ===
@app.post("/register")
def register(data: RegisterModel, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(data.password)
    new_user = User(email=data.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User created"}

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/bind-token")
def bind_token(token: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(Device).filter(Device.token == token).first()
    if existing:
        raise HTTPException(status_code=400, detail="Token already bound")
    device = Device(token=token, user_id=user.id)
    db.add(device)
    db.commit()
    return {"msg": "Token bound to user"}

@app.post("/device/settings")
def update_settings(data: SettingsModel, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user.device:
        raise HTTPException(status_code=404, detail="No device bound")
    user.device.settings = json.dumps(data.settings)
    db.commit()
    return {"msg": "Settings updated"}

@app.get("/api/device/config")
def get_config(token: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.token == token).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return json.loads(device.settings or '{}')
