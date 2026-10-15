import os
import re
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, Field


DB_PATH = os.getenv("NEXORA_DB", "nexora.db")
TOKEN_SECRET = os.getenv("NEXORA_TOKEN_SECRET", "")


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                bio TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            );
        """)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_db()
    yield


app = FastAPI(
    title="NEXORA API",
    version="1.0.0",
    lifespan=lifespan,
)


def now():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: bytes | None = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
    )
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str):
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=2**14,
            r=8,
            p=1,
            dklen=len(expected),
        )
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def hash_token(token: str):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RegisterRequest(BaseModel):
    phone: str = Field(min_length=5, max_length=25)
    username: str = Field(min_length=3, max_length=24)
    display_name: str = Field(min_length=1, max_length=60)
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=10, max_length=128)


class ProfileUpdate(BaseModel):
    display_name: str = Field(min_length=1, max_length=60)
    bio: str = Field(default="", max_length=250)


class SendMessageRequest(BaseModel):
    receiver_username: str = Field(min_length=3, max_length=24)
    body: str = Field(min_length=1, max_length=4000)


def get_current_user(
    authorization: str | None = Header(default=None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    token = authorization.removeprefix("Bearer ").strip()

    if not token or len(token) > 500:
        raise HTTPException(status_code=401, detail="Invalid session")

    with connect_db() as db:
        row = db.execute("""
            SELECT users.id, users.username, users.phone,
                   users.display_name, users.bio
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
        """, (hash_token(token),)).fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid session")

    return dict(row)


@app.get("/")
def home():
    return {
        "app": "NEXORA",
        "status": "running",
        "message": "NEXORA API is ready",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=201)
def register(data: RegisterRequest):
    username = data.username.lower().strip()
    phone = data.phone.strip()
    display_name = data.display_name.strip()

    if not re.fullmatch(r"[a-z0-9_.]{3,24}", username):
        raise HTTPException(
            status_code=400,
            detail="Username may contain lowercase letters, numbers, _ and .",
        )

    if not phone or not display_name:
        raise HTTPException(status_code=400, detail="Invalid profile details")

    password_hash = hash_password(data.password)

    try:
        with connect_db() as db:
            cursor = db.execute("""
                INSERT INTO users (
                    phone, username, display_name,
                    password_hash, created_at
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                phone,
                username,
                display_name,
                password_hash,
                now(),
            ))
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Username already exists",
        )

    return {
        "id": user_id,
        "username": username,
        "display_name": display_name,
        "message": "Account created. Please log in.",
    }


@app.post("/login")
def login(data: LoginRequest):
    username = data.username.lower().strip()

    with connect_db() as db:
        user = db.execute("""
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        if not user or not verify_password(data.password, user["password_hash"]):
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password",
            )

        token = secrets.token_urlsafe(32)

        db.execute("""
            INSERT INTO sessions (token_hash, user_id, created_at)
            VALUES (?, ?, ?)
        """, (hash_token(token), user["id"], now()))

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get("/me")
def my_profile(user=Depends(get_current_user)):
    return user


@app.put("/me")
def update_profile(
    data: ProfileUpdate,
    user=Depends(get_current_user),
):
    with connect_db() as db:
        db.execute("""
            UPDATE users
            SET display_name = ?, bio = ?
            WHERE id = ?
        """, (
            data.display_name.strip(),
            data.bio.strip(),
            user["id"],
        ))

    return {"message": "Profile updated"}


@app.get("/users/{username}")
def find_user(
    username: str,
    user=Depends(get_current_user),
):
    username = username.lower().strip()

    with connect_db() as db:
        row = db.execute("""
            SELECT username, display_name, bio
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    return dict(row)


@app.post("/messages", status_code=201)
def send_message(
    data: SendMessageRequest,
    user=Depends(get_current_user),
):
    receiver_username = data.receiver_username.lower().strip()
    body = data.body.strip()

    if not body:
        raise HTTPException(status_code=400, detail="Message is empty")

    with connect_db() as db:
        receiver = db.execute("""
            SELECT id FROM users WHERE username = ?
        """, (receiver_username,)).fetchone()

        if not receiver:
            raise HTTPException(status_code=404, detail="Recipient not found")

        cursor = db.execute("""
            INSERT INTO messages (
                sender_id, receiver_id, body, created_at
            ) VALUES (?, ?, ?, ?)
        """, (
            user["id"],
            receiver["id"],
            body,
            now(),
        ))

        message_id = cursor.lastrowid

    return {
        "id": message_id,
        "message": "Message saved",
    }


@app.get("/messages/{username}")
def get_messages(
    username: str,
    user=Depends(get_current_user),
):
    username = username.lower().strip()

    with connect_db() as db:
        other = db.execute("""
            SELECT id FROM users WHERE username = ?
        """, (username,)).fetchone()

        if not other:
            raise HTTPException(status_code=404, detail="User not found")

        rows = db.execute("""
            SELECT
                messages.id,
                sender.username AS sender,
                receiver.username AS receiver,
                messages.body,
                messages.created_at
            FROM messages
            JOIN users AS sender ON sender.id = messages.sender_id
            JOIN users AS receiver ON receiver.id = messages.receiver_id
            WHERE
                (messages.sender_id = ? AND messages.receiver_id = ?)
                OR
                (messages.sender_id = ? AND messages.receiver_id = ?)
            ORDER BY messages.id ASC
            LIMIT 500
        """, (
            user["id"],
            other["id"],
            other["id"],
            user["id"],
        )).fetchall()

    return {"messages": [dict(row) for row in rows]}
