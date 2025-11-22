import os
import json
import bcrypt
import streamlit as st

from database import load_all_users_from_db, save_user_to_db

USER_DB_FILE = "users.json"  # used only for one-time migration


def hash_password(plain: str) -> str:
    """Hash a plain password using bcrypt."""
    if not plain:
        return ""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain: str, stored: str) -> bool:
    """
    Check a plain password against a stored hash.

    Legacy behaviour:
    - If stored does NOT start with '$2b$', treat it as plain text and compare directly.
    """
    if not stored:
        return False

    if not stored.startswith("$2b$"):
        return plain == stored

    try:
        return bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        return False


def load_users():
    """
    Load registered users from SQLite.

    If SQLite is empty but users.json exists, migrate those users once.
    """
    users_from_db = load_all_users_from_db()
    if users_from_db:
        return users_from_db

    if os.path.exists(USER_DB_FILE):
        try:
            with open(USER_DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for uname, profile in data.items():
                        if isinstance(profile, dict):
                            profile.setdefault("username", uname)
                            save_user_to_db(profile)
                    return load_all_users_from_db()
        except Exception:
            return {}

    return {}


def save_users(users: dict):
    """
    Save users into SQLite via save_user_to_db.
    """
    if not isinstance(users, dict):
        return
    for uname, profile in users.items():
        if not isinstance(profile, dict):
            continue
        profile.setdefault("username", uname)
        save_user_to_db(profile)


def get_admin_credentials():
    """
    Load admin credentials from Streamlit secrets or environment variables.

    Priority:
    1. st.secrets['admin']['username'] / ['password'] if available
    2. ENV: ADMIN_USERNAME / ADMIN_PASSWORD
    """
    admin_user = None
    admin_pass = None

    try:
        if "admin" in st.secrets:
            admin_cfg = st.secrets["admin"]
            try:
                admin_user = admin_cfg["username"]
                admin_pass = admin_cfg["password"]
            except Exception:
                pass
    except Exception:
        pass

    if not admin_user:
        admin_user = os.getenv("ADMIN_USERNAME")
    if not admin_pass:
        admin_pass = os.getenv("ADMIN_PASSWORD")

    return admin_user, admin_pass