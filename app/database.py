"""SQLite persistence for assessment history and human review decisions."""
import json
import os
from pathlib import Path
import sqlite3
from typing import Any


DATABASE_PATH = Path(os.getenv("SECURELENS_DB_PATH", "data/securelens.db"))


def connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(DATABASE_PATH)
    database.row_factory = sqlite3.Row
    return database


def initialize_database() -> None:
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS assessments (
            assessment_id TEXT PRIMARY KEY, project_name TEXT NOT NULL, phase TEXT NOT NULL,
            risk_level TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending_review',
            payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TEXT, reviewer_note TEXT
        );
        CREATE TABLE IF NOT EXISTS remediation_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT NOT NULL, action_text TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open', owner TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(assessment_id) REFERENCES assessments(assessment_id)
        );
        CREATE TABLE IF NOT EXISTS knowledge_documents (
            document_id TEXT PRIMARY KEY, filename TEXT NOT NULL, framework TEXT NOT NULL,
            content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS knowledge_chunks (
            chunk_id TEXT PRIMARY KEY, document_id TEXT NOT NULL, content TEXT NOT NULL,
            embedding TEXT, FOREIGN KEY(document_id) REFERENCES knowledge_documents(document_id)
        );
        """)


def save_assessment(payload: dict[str, Any]) -> None:
    with connection() as db:
        db.execute("INSERT INTO assessments (assessment_id, project_name, phase, risk_level, payload) VALUES (?, ?, ?, ?, ?)", (payload["assessment_id"], payload["project_name"], payload["phase"], payload["risk_level"], json.dumps(payload)))
        db.executemany("INSERT INTO remediation_actions (assessment_id, action_text) VALUES (?, ?)", [(payload["assessment_id"], action) for action in payload["next_actions"]])


def get_assessment(assessment_id: str) -> dict[str, Any] | None:
    with connection() as db:
        row = db.execute("SELECT payload, status, reviewer_note FROM assessments WHERE assessment_id = ?", (assessment_id,)).fetchone()
        if not row:
            return None
        payload = json.loads(row["payload"])
        payload.update({"status": row["status"], "reviewer_note": row["reviewer_note"]})
        payload["remediations"] = [dict(item) for item in db.execute("SELECT id, action_text, status, owner, updated_at FROM remediation_actions WHERE assessment_id = ?", (assessment_id,))]
        return payload


def review_assessment(assessment_id: str, status: str, note: str) -> bool:
    with connection() as db:
        return bool(db.execute("UPDATE assessments SET status = ?, reviewer_note = ?, reviewed_at = CURRENT_TIMESTAMP WHERE assessment_id = ?", (status, note, assessment_id)).rowcount)


def update_remediation(action_id: int, status: str, owner: str | None) -> bool:
    with connection() as db:
        return bool(db.execute("UPDATE remediation_actions SET status = ?, owner = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (status, owner, action_id)).rowcount)
