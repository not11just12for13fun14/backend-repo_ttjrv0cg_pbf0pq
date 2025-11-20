import os
from typing import Any, Dict, List, Optional
from datetime import datetime
from pymongo import MongoClient

DATABASE_URL = os.environ.get("DATABASE_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.environ.get("DATABASE_NAME", "quiz_app")

_client: Optional[MongoClient] = None
_db = None


def get_db():
    global _client, _db
    if _db is None:
        _client = MongoClient(DATABASE_URL)
        _db = _client[DATABASE_NAME]
    return _db


def create_document(collection_name: str, data: Dict[str, Any]) -> str:
    db = get_db()
    now = datetime.utcnow()
    data.setdefault("createdAt", now)
    data.setdefault("updatedAt", now)
    result = db[collection_name].insert_one(data)
    return str(result.inserted_id)


def get_documents(collection_name: str, filter_dict: Dict[str, Any] | None = None, limit: int = 100) -> List[Dict[str, Any]]:
    db = get_db()
    filter_dict = filter_dict or {}
    cursor = db[collection_name].find(filter_dict).limit(limit)
    return [
        {**doc, "_id": str(doc.get("_id"))}
        for doc in cursor
    ]
