from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

# Users Collection Schema
class User(BaseModel):
    uid: str
    role: str  # "superadmin" | "teacher" | "student"
    email: str
    name: str

# Quizzes Collection Schema
class QuestionOption(BaseModel):
    id: str
    text: str
    isCorrect: bool = False

class Question(BaseModel):
    id: str
    text: str
    options: List[QuestionOption]
    points: int = 1

class Quiz(BaseModel):
    id: str
    title: str
    code: str
    timeLimit: int
    version: int = 1
    createdBy: str
    questions: List[Question] = []
    createdAt: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updatedAt: Optional[datetime] = Field(default_factory=datetime.utcnow)

# Attempts Collection Schema
class Attempt(BaseModel):
    quizId: str
    studentId: str
    answers: Dict[str, Any] = {}
    score: float = 0
    startTime: Optional[datetime] = Field(default_factory=datetime.utcnow)
    endTime: Optional[datetime] = None
    suspiciousEvents: List[Dict[str, Any]] = []
