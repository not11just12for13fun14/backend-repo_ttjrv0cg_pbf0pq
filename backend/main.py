from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import get_db, create_document, get_documents
from schemas import User, Quiz, Attempt

SECRET_KEY = "supersecretkey"  # in real deployment, use env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str
    password: str


# Simple in-db user storage with hashed passwords (seed on first run)

def seed_super_admin():
    db = get_db()
    existing = db["user"].find_one({"email": "admin@university.edu"})
    if not existing:
        db["user"].insert_one({
            "uid": "admin-1",
            "role": "superadmin",
            "email": "admin@university.edu",
            "name": "Super Admin",
            "password": pwd_context.hash("admin123")
        })


seed_super_admin()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid authentication scheme")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        email: str = payload.get("email")
        role: str = payload.get("role")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"uid": user_id, "email": email, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/")
async def root():
    return {"message": "Backend OK", "time": datetime.utcnow().isoformat()}


@app.get("/test")
async def test():
    db = get_db()
    # list collections
    collections = await _list_collections_async(db)
    return {
        "backend": "FastAPI",
        "database": "MongoDB",
        "database_url": "env:DATABASE_URL",
        "database_name": db.name,
        "connection_status": "connected",
        "collections": collections,
    }


async def _list_collections_async(db):
    # synchronous client; wrap simply
    try:
        return db.list_collection_names()
    except Exception:
        return []


@app.post("/auth/login", response_model=Token)
async def login(payload: LoginRequest):
    db = get_db()
    user = db["user"].find_one({"email": payload.email})
    if not user or not pwd_context.verify(payload.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({
        "sub": user["uid"],
        "email": user["email"],
        "role": user["role"],
    })
    return Token(access_token=token)


# Quiz CRUD minimal endpoints
class QuizCreateRequest(BaseModel):
    title: str
    timeLimit: int
    questions: List[Dict[str, Any]] = []


@app.post("/quizzes")
async def create_quiz(data: QuizCreateRequest, user=Depends(get_current_user)):
    if user["role"] not in ("superadmin", "teacher"):
        raise HTTPException(status_code=403, detail="Forbidden")
    db = get_db()
    code = generate_quiz_code()
    doc = {
        "id": code,
        "title": data.title,
        "code": code,
        "timeLimit": data.timeLimit,
        "version": 1,
        "createdBy": user["uid"],
        "questions": data.questions,
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow(),
    }
    db["quiz"].insert_one(doc)
    return {"id": code, "code": code}


@app.get("/quizzes/{code}")
async def get_quiz_by_code(code: str, user: Optional[dict] = Depends(lambda authorization=Header(None): None)):
    db = get_db()
    quiz = db["quiz"].find_one({"code": code}, {"_id": 0})
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")
    # do not leak correct answers here
    for q in quiz.get("questions", []):
        for opt in q.get("options", []):
            opt.pop("isCorrect", None)
    return quiz


class AttemptStart(BaseModel):
    quizCode: str
    studentId: str


@app.post("/attempts/start")
async def start_attempt(data: AttemptStart):
    db = get_db()
    quiz = db["quiz"].find_one({"code": data.quizCode})
    if not quiz:
        raise HTTPException(status_code=404, detail="Quiz not found")
    attempt = {
        "quizId": quiz.get("id"),
        "studentId": data.studentId,
        "answers": {},
        "score": 0,
        "startTime": datetime.utcnow(),
        "endTime": None,
        "suspiciousEvents": [],
    }
    id_ = db["attempt"].insert_one(attempt).inserted_id
    return {"attemptId": str(id_)}


class AttemptSubmit(BaseModel):
    attemptId: str
    answers: Dict[str, Any]


@app.post("/attempts/submit")
async def submit_attempt(data: AttemptSubmit):
    from bson import ObjectId
    db = get_db()
    att = db["attempt"].find_one({"_id": ObjectId(data.attemptId)})
    if not att:
        raise HTTPException(status_code=404, detail="Attempt not found")
    quiz = db["quiz"].find_one({"id": att["quizId"]})
    score = calculate_score(quiz, data.answers)
    db["attempt"].update_one({"_id": ObjectId(data.attemptId)}, {"$set": {"answers": data.answers, "score": score, "endTime": datetime.utcnow()}})
    return {"score": score}


class SuspiciousEvent(BaseModel):
    attemptId: str
    type: str
    meta: Optional[Dict[str, Any]] = None


@app.post("/monitor/log")
async def log_event(event: SuspiciousEvent):
    from bson import ObjectId
    db = get_db()
    db["attempt"].update_one({"_id": ObjectId(event.attemptId)}, {"$push": {"suspiciousEvents": {"type": event.type, "meta": event.meta, "time": datetime.utcnow()}}})
    return {"status": "logged"}


@app.get("/dashboard/stats")
async def dashboard_stats(user=Depends(get_current_user)):
    if user["role"] not in ("superadmin", "teacher"):
        raise HTTPException(status_code=403, detail="Forbidden")
    db = get_db()
    quizzes = db["quiz"].count_documents({})
    attempts = db["attempt"].count_documents({})
    active = db["attempt"].count_documents({"endTime": None})
    return {"quizzes": quizzes, "attempts": attempts, "activeAttempts": active}


def calculate_score(quiz: Dict[str, Any], answers: Dict[str, Any]) -> float:
    total = 0
    score = 0
    for q in quiz.get("questions", []):
        total += q.get("points", 1)
        chosen = answers.get(q["id"])  # option id
        for opt in q.get("options", []):
            if opt.get("id") == chosen and opt.get("isCorrect"):
                score += q.get("points", 1)
    return score


def generate_quiz_code() -> str:
    import random, string
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
