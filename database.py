import os
import json
import sqlite3
import datetime

# Directories & files
# Directories & files
BOOKS_DIR = "books"
UNREADABLE_FILE = "unreadable_books.json"
FAVOURITES_FILE = "favourites.json"
PRACTICE_CANDIDATES_FILE = "practice_candidates.json"
APPROVED_PRACTICES_FILE = "approved_practices.json"

# Directories for guidance media
GUIDANCE_AUDIO_DIR = "guidance_audio"
GUIDANCE_MEDIA_DIR = "guidance_media"

os.makedirs(GUIDANCE_AUDIO_DIR, exist_ok=True)
os.makedirs(GUIDANCE_MEDIA_DIR, exist_ok=True)

SESSIONS_FILE = "sessions.json"
SESSION_TTL_MINUTES = 40

# SQLite DB for users
DB_FILE = "dharma_app.db"
GUIDANCE_AUDIO_DIR = "guidance_audio"
SESSIONS_FILE = "sessions.json"

# Session timeout (already used in your app)
SESSION_TTL_MINUTES = 40

# SQLite DB for users
DB_FILE = "dharma_app.db"

os.makedirs(GUIDANCE_AUDIO_DIR, exist_ok=True)


# ---------- SQLITE USER DB ----------

def init_db():
    """Initialise the SQLite database for user storage."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                first_name TEXT,
                last_name TEXT,
                year_of_birth INTEGER,
                language TEXT,
                location TEXT,
                data TEXT
            )
            """
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def save_user_to_db(profile: dict):
    """Insert or update a single user profile into SQLite."""
    if not profile:
        return
    username = profile.get("username")
    if not username:
        return

    password_val = profile.get("password", "")
    first_name = profile.get("first_name")
    last_name = profile.get("last_name")
    year = profile.get("year_of_birth")
    language = profile.get("language")
    location = profile.get("location")
    data_json = json.dumps(profile, ensure_ascii=False)

    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO users (
                username, password, first_name, last_name,
                year_of_birth, language, location, data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                password_val,
                first_name,
                last_name,
                year,
                language,
                location,
                data_json,
            ),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def load_user_from_db(username: str) -> dict:
    """Load a single user profile from SQLite by username."""
    if not username:
        return {}
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT password, data FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return {}
    else:
        try:
            conn.close()
        except Exception:
            pass

    if not row:
        return {}

    password_val, data_json = row
    try:
        profile = json.loads(data_json) if data_json else {}
    except Exception:
        profile = {}

    profile.setdefault("username", username)
    if password_val:
        profile["password"] = password_val
    return profile


def load_all_users_from_db() -> dict:
    """Load all user profiles from SQLite into a dict keyed by username."""
    users = {}
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT username, data FROM users")
        rows = cur.fetchall()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return users
    else:
        try:
            conn.close()
        except Exception:
            pass

    for username, data_json in rows:
        try:
            profile = json.loads(data_json) if data_json else {}
        except Exception:
            profile = {}
        profile.setdefault("username", username)
        users[username] = profile
    return users


# Ensure DB exists
init_db()


# ---------- SESSIONS (JSON) ----------

def load_sessions():
    """Load persistent login sessions from disk."""
    if not os.path.exists(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
    except Exception:
        return {}


def save_sessions(sessions: dict):
    """Persist login sessions to disk."""
    try:
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ---------- BOOK LIST / UNREADABLE ----------

def list_book_names():
    if not os.path.exists(BOOKS_DIR):
        return []
    files = [
        f for f in os.listdir(BOOKS_DIR)
        if f.lower().endswith((".pdf", ".epub"))
    ]
    return sorted(files)


def load_unreadable():
    if not os.path.exists(UNREADABLE_FILE):
        return {}
    try:
        with open(UNREADABLE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}
    except Exception:
        return {}


# ---------- FAVOURITES ----------

def load_favourites():
    if not os.path.exists(FAVOURITES_FILE):
        return {}
    try:
        with open(FAVOURITES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
    except json.JSONDecodeError:
        return {}
    except Exception:
        return {}


def save_favourites(favs: dict):
    try:
        with open(FAVOURITES_FILE, "w", encoding="utf-8") as f:
            json.dump(favs, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ---------- PRACTICE CANDIDATES / APPROVED PRACTICES ----------

def load_approved_practices():
    if not os.path.exists(APPROVED_PRACTICES_FILE):
        return {"mantra": [], "meditation": []}
    try:
        with open(APPROVED_PRACTICES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("mantra", [])
                data.setdefault("meditation", [])
                return data
            return {"mantra": [], "meditation": []}
    except json.JSONDecodeError:
        return {"mantra": [], "meditation": []}
    except Exception:
        return {"mantra": [], "meditation": []}


def save_approved_practices(data: dict):
    try:
        with open(APPROVED_PRACTICES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_practice_candidates():
    if not os.path.exists(PRACTICE_CANDIDATES_FILE):
        return []
    try:
        with open(PRACTICE_CANDIDATES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and isinstance(data.get("candidates"), list):
                return data["candidates"]
            return []
    except json.JSONDecodeError:
        return []
    except Exception:
        return []


def save_practice_candidates(candidates: list):
    try:
        with open(PRACTICE_CANDIDATES_FILE, "w", encoding="utf-8") as f:
            json.dump(candidates, f, indent=2, ensure_ascii=False)
    except Exception:
        pass