from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta, timezone
import jwt
import bcrypt
import re
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Create the main app without a prefix
app = FastAPI(title="NAITS Student Portal API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Enums
class UserRole(str, Enum):
    STUDENT = "student"
    ADMIN = "admin"

class PaymentStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    DISPUTED = "disputed"
    REFUNDED = "refunded"

class FeeType(str, Enum):
    MEMBERSHIP = "membership"
    EVENT = "event"
    EXAM = "exam"

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    student_id: Optional[str] = None  # For students only
    username: Optional[str] = None    # For admins only
    email: Optional[str] = None       # For students only
    password_hash: str
    role: UserRole
    department: Optional[str] = None
    level: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    student_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: str
    role: UserRole
    department: Optional[str] = None
    level: Optional[str] = None

class UserLogin(BaseModel):
    identifier: str  # Can be student_id or username
    password: str

class Payment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    fee_type: FeeType
    amount: float
    currency: str = "NGN"
    gateway_ref: Optional[str] = None
    status: PaymentStatus
    paid_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PaymentCreate(BaseModel):
    fee_type: FeeType
    amount: float

class Receipt(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    payment_id: str
    user_id: str
    student_name: str
    student_id: str
    fee_type: str
    amount: float
    currency: str
    transaction_ref: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Utility Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def validate_student_id(student_id: str) -> bool:
    pattern = r'^IMT/\d{2}U/\d{4}$'
    return bool(re.match(pattern, student_id))

def validate_student_email(email: str) -> bool:
    pattern = r'^\d{2}u\d+@students\.mau\.edu\.ng$'
    return bool(re.match(pattern, email))

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
@api_router.post("/register")
async def register(user_data: UserCreate):
    # Validation based on role
    if user_data.role == UserRole.STUDENT:
        if not user_data.student_id or not user_data.email:
            raise HTTPException(status_code=400, detail="Student ID and email required for students")
        
        if not validate_student_id(user_data.student_id):
            raise HTTPException(status_code=400, detail="Invalid student ID format. Use IMT/YYU/XXXX")
        
        if not validate_student_email(user_data.email):
            raise HTTPException(status_code=400, detail="Invalid student email format. Use YYuXXX@students.mau.edu.ng")
        
        # Check if student already exists
        existing = await db.users.find_one({"student_id": user_data.student_id})
        if existing:
            raise HTTPException(status_code=400, detail="Student ID already registered")
    
    elif user_data.role == UserRole.ADMIN:
        if not user_data.username:
            raise HTTPException(status_code=400, detail="Username required for admins")
        
        # Check if admin already exists
        existing = await db.users.find_one({"username": user_data.username})
        if existing:
            raise HTTPException(status_code=400, detail="Username already taken")
    
    # Create user
    user_dict = user_data.dict(exclude={'password'})
    user_dict['password_hash'] = hash_password(user_data.password)
    user_obj = User(**user_dict)
    
    await db.users.insert_one(user_obj.dict())
    
    return {"message": "User registered successfully", "user_id": user_obj.id}

@api_router.post("/login")
async def login(login_data: UserLogin):
    # Find user by student_id or username
    user = await db.users.find_one({
        "$or": [
            {"student_id": login_data.identifier},
            {"username": login_data.identifier}
        ]
    })
    
    if not user or not verify_password(login_data.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create token
    token = create_access_token(data={"sub": user['id'], "role": user['role']})
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user['id'],
            "role": user['role'],
            "student_id": user.get('student_id'),
            "username": user.get('username'),
            "email": user.get('email')
        }
    }

@api_router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@api_router.post("/payments/create")
async def create_payment(payment_data: PaymentCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(status_code=403, detail="Only students can make payments")
    
    # Create payment record
    payment_dict = payment_data.dict()
    payment_dict['user_id'] = current_user.id
    payment_dict['status'] = PaymentStatus.PENDING
    payment_dict['gateway_ref'] = f"PAY_{uuid.uuid4().hex[:12].upper()}"
    
    payment_obj = Payment(**payment_dict)
    await db.payments.insert_one(payment_obj.dict())
    
    # Mock payment completion (in real app, this would be handled by Paystack webhook)
    payment_obj.status = PaymentStatus.COMPLETED
    payment_obj.paid_at = datetime.now(timezone.utc)
    
    await db.payments.update_one(
        {"id": payment_obj.id},
        {"$set": {"status": payment_obj.status, "paid_at": payment_obj.paid_at}}
    )
    
    return {"message": "Payment processed successfully", "payment_id": payment_obj.id, "reference": payment_obj.gateway_ref}

@api_router.get("/payments/history")
async def get_payment_history(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(status_code=403, detail="Only students can view payment history")
    
    payments = await db.payments.find({"user_id": current_user.id}).to_list(1000)
    return [Payment(**payment) for payment in payments]

@api_router.get("/payments/{payment_id}/receipt")
async def get_receipt(payment_id: str, current_user: User = Depends(get_current_user)):
    payment = await db.payments.find_one({"id": payment_id})
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    # Check if user owns this payment or is admin
    if current_user.role == UserRole.STUDENT and payment['user_id'] != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get student info
    student = await db.users.find_one({"id": payment['user_id']})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    receipt_data = {
        "payment_id": payment_id,
        "user_id": payment['user_id'],
        "student_name": f"Student {student['student_id']}",  # In real app, store actual names
        "student_id": student['student_id'],
        "fee_type": payment['fee_type'],
        "amount": payment['amount'],
        "currency": payment['currency'],
        "transaction_ref": payment['gateway_ref'],
        "paid_at": payment.get('paid_at', payment['created_at'])
    }
    
    return receipt_data

@api_router.get("/admin/payments")
async def get_all_payments(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    payments = await db.payments.find().to_list(1000)
    total_revenue = sum(p['amount'] for p in payments if p['status'] == 'completed')
    
    return {
        "payments": [Payment(**payment) for payment in payments],
        "total_revenue": total_revenue,
        "total_count": len(payments)
    }

@api_router.put("/admin/payments/{payment_id}/status")
async def update_payment_status(payment_id: str, status: PaymentStatus, current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.payments.update_one(
        {"id": payment_id},
        {"$set": {"status": status}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    return {"message": "Payment status updated successfully"}

# Remove seed users - let users register naturally
@app.on_event("startup")
async def startup_tasks():
    logger.info("NAITS Student Portal started successfully")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()