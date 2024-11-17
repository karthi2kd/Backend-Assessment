from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from jose import jwt, JWTError
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import os
import shutil
import datetime

# App Initialization
app = FastAPI()

# Database Setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
Base = declarative_base()
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Encryption Key
SECRET_KEY = Fernet.generate_key()
fernet = Fernet(SECRET_KEY)

# Authentication Config
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = "your_jwt_secret_key"
ALGORITHM = "HS256"

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)  # "ops" or "client"

class FileMeta(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    uploader_id = Column(Integer)

Base.metadata.create_all(bind=engine)

# Helper Functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# API Endpoints
@app.post("/signup")
def signup(username: str = Form(...), password: str = Form(...), role: str = Form(...), db: SessionLocal = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = hash_password(password)
    new_user = User(username=username, password=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token_data = {"sub": user.username, "role": user.role}
    token = create_access_token(data=token_data)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/ops/upload")
def upload_file(token: str = Depends(oauth2_scheme), file: UploadFile = File(...), db: SessionLocal = Depends(get_db)):
    payload = decode_access_token(token)
    if payload.get("role") != "ops":
        raise HTTPException(status_code=403, detail="Only Ops users can upload files")
    if file.content_type not in ["application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                 "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                                 "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    filepath = f"uploads/{file.filename}"
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    new_file = FileMeta(filename=file.filename, uploader_id=user.id)
    db.add(new_file)
    db.commit()
    return {"message": "File uploaded successfully"}

@app.get("/client/files")
def list_files(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = decode_access_token(token)
    if payload.get("role") != "client":
        raise HTTPException(status_code=403, detail="Only Client users can access files")
    files = db.query(FileMeta).all()
    return {"files": [{"id": f.id, "filename": f.filename} for f in files]}

@app.get("/client/download/{file_id}")
def download_file(file_id: int, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    payload = decode_access_token(token)
    if payload.get("role") != "client":
        raise HTTPException(status_code=403, detail="Only Client users can download files")
    file = db.query(FileMeta).filter(FileMeta.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    encrypted_link = fernet.encrypt(file.filename.encode()).decode()
    return {"download_link": f"/download/{encrypted_link}"}

@app.get("/download/{encrypted_link}")
def serve_file(encrypted_link: str):
    try:
        filename = fernet.decrypt(encrypted_link.encode()).decode()
        filepath = f"uploads/{filename}"
        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="File not found")
        return {"message": f"File {filename} can be downloaded"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid link")


@app.get("/")
def read_root():
    return {"message": "Welcome to the Secure File Sharing System"}