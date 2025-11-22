import os
import json
import datetime
import subprocess
import secrets

import streamlit as st

from ui import apply_global_css, render_answer_html, render_source_html, render_mantra_html
from rag import retrieve_passages, answer_question, generate_styled_image
from database import (
    load_sessions,
    save_sessions,
    list_book_names,
    load_unreadable,
    load_favourites,
    save_favourites,
    load_approved_practices,
    save_approved_practices,
    load_practice_candidates,
    save_practice_candidates,
    SESSION_TTL_MINUTES,
    GUIDANCE_AUDIO_DIR,
    GUIDANCE_MEDIA_DIR,
)
from auth import (
    hash_password,
    check_password,
    load_users,
    save_users,
    get_admin_credentials,
)
from admin_tools import (
    scan_practice_candidates_from_chroma,
    fetch_online_practices,
)

# ---------- PAGE CONFIG (DO THIS FIRST) ----------
st.set_page_config(page_title="Dharma Story Chat", page_icon="📚", layout="wide")

st.write("✅ App file loaded. Initializing...")  # DEBUG LINE so page is never blank

apply_global_css()


# ---------- CONSTANTS ----------

BOOKS_DIR = "books"
COLLECTION_NAME = "saint_books"
UNREADABLE_FILE = "unreadable_books.json"
CHROMA_PATH = "./chroma_db"
USER_DB_FILE = "users.json"
FAVOURITES_FILE = "favourites.json"
PRACTICE_CANDIDATES_FILE = "practice_candidates.json"
APPROVED_PRACTICES_FILE = "approved_practices.json"





# ---------- DAILY REFLECTION ----------

def get_daily_reflection(age_group):
    """
    Return a short, gentle reflection line for the day.

    We keep this simple and static for now, rotating through a small set
    based on the current date, and adjust tone slightly for child/adult.
    """
    # A few adult-oriented reflections
    adult_reflections = [
        "Pause once today and remember: every small act of kindness can be placed at the Lord's feet like a flower.",
        "When the mind becomes restless, gently return to the breath and recall one quality of your chosen deity.",
        "Before sleep, think of one moment today where you could have been softer. Offer that moment into inner light.",
        "Wherever you are today, imagine you are standing in a sacred space. Speak and act as if the Divine is listening.",
        "If worry arises, quietly say: 'I am not alone in this. May I act with dharma and trust.'",
    ]

    # A few child-friendly reflections
    child_reflections = [
        "Can you share something today and imagine you are sharing it with God?",
        "If you feel angry today, take three slow breaths and think of your favourite form of the Divine smiling at you.",
        "Try to tell the truth today even in small things. Saints smile when you are honest.",
        "Before you sleep, thank the Divine for one happy moment from your day.",
        "When you see someone sad today, can you say one kind word for them in your heart?",
    ]

    today = datetime.date.today()
    idx = today.toordinal()

    if age_group == "child":
        items = child_reflections
    else:
        items = adult_reflections

    return items[idx % len(items)]


def get_current_username():
    profile = st.session_state.get("user_profile") or {}
    return profile.get("username") or st.session_state.get("user_name")




# ---------- AUTH / ROLE SESSION STATE ----------

if "role" not in st.session_state:
    # "guest" (not logged in), "admin", or "user"
    st.session_state["role"] = "guest"
if "user_name" not in st.session_state:
    st.session_state["user_name"] = None
if "age_group" not in st.session_state:
    # "child", "adult", or None
    st.session_state["age_group"] = None
if "user_profile" not in st.session_state:
    # store extra user info such as first/last name, language, location, dob
    st.session_state["user_profile"] = {}

# Show/hide user history panel
if "show_history_panel" not in st.session_state:
    # whether to show the user's history panel
    st.session_state["show_history_panel"] = False

# Persistent session token so refresh does not force re-login (per browser URL)
if "session_token" not in st.session_state:
    st.session_state["session_token"] = None

# Attempt auto-restore of login if we are currently a guest
# and a valid session token is present in the URL query params.
current_role = st.session_state.get("role", "guest")
if current_role == "guest":
    token_list = st.query_params.get("session", [])
    if isinstance(token_list, str):
        token_list = [token_list]
    if token_list:
        token = token_list[0]
        sessions = load_sessions()
        sess = sessions.get(token)
        if sess:
            # Check expiry based on creation time
            created_str = sess.get("created_at")
            expired = False
            if created_str:
                try:
                    created_dt = datetime.datetime.fromisoformat(created_str)
                    now_dt = datetime.datetime.now()
                    if now_dt - created_dt > datetime.timedelta(minutes=SESSION_TTL_MINUTES):
                        expired = True
                except Exception:
                    expired = True
            if expired:
                sessions.pop(token, None)
                save_sessions(sessions)
            else:
                role_from_sess = sess.get("role")
                username_from_sess = sess.get("username")
                if role_from_sess == "admin":
                    # Auto-restore admin
                    st.session_state["role"] = "admin"
                    st.session_state["user_name"] = username_from_sess or "admin"
                    st.session_state["age_group"] = None
                    st.session_state["user_profile"] = {}
                    st.session_state["session_token"] = token
                elif role_from_sess == "user" and username_from_sess:
                    # Auto-restore user profile from users.json
                    users = load_users()
                    profile = users.get(username_from_sess)
                    if profile:
                        year = profile.get("year_of_birth")
                        age_group = None
                        if isinstance(year, int):
                            current_year = datetime.datetime.now().year
                            age = current_year - year
                            age_group = "adult" if age >= 22 else "child"
                        st.session_state["role"] = "user"
                        st.session_state["user_name"] = profile.get("first_name") or username_from_sess
                        st.session_state["age_group"] = age_group
                        st.session_state["user_profile"] = profile
                        st.session_state["session_token"] = token
    # If token invalid or expired, we remain guest and show normal login gate.



# ---------- SESSION STATE FOR CHAT ----------

if "messages" not in st.session_state:
    st.session_state["messages"] = []
if "generate_image" not in st.session_state:
    st.session_state["generate_image"] = False
if "online_search_results" not in st.session_state:
    # Holds last fetched online suggestions for admin internet search
    st.session_state["online_search_results"] = []

# ---------- LOGIN GATE (FULL PAGE FOR GUESTS) ----------

current_role = st.session_state.get("role", "guest")

if current_role == "guest":
    # Simple centered layout for login/signup
    st.title("📚 Dharma Story Chat")
    st.subheader("Sign in to continue")
    st.markdown("---")

    # Choose whether logging in as User or Admin
    login_mode = st.radio(
        "Login as:",
        ["User", "Admin"],
        horizontal=True,
        key="login_mode",
    )

    if login_mode == "Admin":
        admin_user, admin_pass = get_admin_credentials()
        if not admin_user or not admin_pass:
            st.info(
                "Admin credentials are not configured.\n\n"
                "Set them via Streamlit secrets under [admin] or environment\n"
                "variables ADMIN_USERNAME and ADMIN_PASSWORD."
            )

        username_input = st.text_input("Admin username", key="admin_username_input")
        password_input = st.text_input("Admin password", type="password", key="admin_password_input")

        if st.button("Sign in as Admin", key="admin_login_submit"):
            if admin_user and admin_pass and username_input == admin_user and password_input == admin_pass:
                st.session_state["role"] = "admin"
                st.session_state["user_name"] = username_input
                st.session_state["age_group"] = None
                st.session_state["user_profile"] = {}

                # Create persistent session token and store
                sessions = load_sessions()
                token = secrets.token_urlsafe(16)
                sessions[token] = {
                    "role": "admin",
                    "username": username_input,
                    "created_at": datetime.datetime.now().isoformat(),
                }
                save_sessions(sessions)
                st.session_state["session_token"] = token

                st.success("Logged in as admin.")
                st.rerun()
            else:
                st.error("Invalid admin credentials.")

    else:  # User login / signup
        # Choose between sign-in and full sign-up
        user_auth_mode = st.radio(
            "Mode:",
            ["Sign in", "Sign up"],
            horizontal=True,
            key="user_auth_mode",
        )

        if user_auth_mode == "Sign in":
            username_input = st.text_input("Username", key="user_login_username")
            password_input = st.text_input("Password", type="password", key="user_login_password")

            if st.button("Sign in as User", key="user_login_submit"):
                if len(password_input.strip()) < 8 or not any(
                    ch in "!@#$%^&*()-_=+[]{};:'\",.<>/?|" for ch in password_input
                ):
                    st.error("Password must be at least 8 characters and contain a special character.")
                else:
                    users = load_users()
                    profile = users.get(username_input)

                    if not profile:
                        st.error("No account found with that username. Please sign up first.")
                    else:
                        stored_password = profile.get("password", "")
                        if not check_password(password_input.strip(), stored_password):
                            st.error("Incorrect password.")
                        else:
                            year = profile.get("year_of_birth")
                            age_group = None
                            if isinstance(year, int):
                                current_year = datetime.datetime.now().year
                                age = current_year - year
                                age_group = "adult" if age >= 22 else "child"

                            st.session_state["role"] = "user"
                            st.session_state["user_name"] = profile.get("first_name") or username_input
                            st.session_state["age_group"] = age_group
                            st.session_state["user_profile"] = profile

                            # Create persistent session token
                            sessions = load_sessions()
                            token = secrets.token_urlsafe(16)
                            sessions[token] = {
                                "role": "user",
                                "username": username_input,
                                "created_at": datetime.datetime.now().isoformat(),
                            }
                            save_sessions(sessions)
                            st.session_state["session_token"] = token

                            st.success(f"Logged in as user ({age_group or 'unknown age'} mode).")
                            st.rerun()

        else:  # Sign up
            username = st.text_input("Choose a username (must be unique)", key="signup_username")
            first_name = st.text_input("First name", key="signup_first_name")
            last_name = st.text_input("Last name", key="signup_last_name")
            year_str = st.text_input("Year of birth (YYYY)", key="signup_yob")

            password_input = st.text_input(
                "Create Password (min 8 chars, include at least one special character)",
                type="password",
                key="signup_password",
            )

            language = st.selectbox(
                "Preferred language",
                [
                    "English",
                    "Hindi",
                    "Telugu",
                    "Tamil",
                    "Kannada",
                    "Malayalam",
                    "Gujarati",
                    "Marathi",
                    "Other",
                ],
                key="signup_lang",
            )

            location = st.text_input(
                "Location (City, Country)",
                key="signup_location",
            )

            if st.button("Sign up", key="user_signup_submit"):
                if not username.strip():
                    st.error("Please choose a username.")
                elif not first_name.strip():
                    st.error("Please enter your first name.")
                elif len(password_input.strip()) < 8 or not any(
                    ch in "!@#$%^&*()-_=+[]{};:'\",.<>/?|" for ch in password_input
                ):
                    st.error("Password must be at least 8 characters and contain a special character.")
                else:
                    try:
                        current_year = datetime.datetime.now().year
                        year = int(year_str)
                        if year < 1900 or year > current_year:
                            st.error("Please enter a valid birth year.")
                        else:
                            users = load_users()
                            if username in users:
                                st.error("That username is already taken. Please choose another.")
                            else:
                                age = current_year - year
                                age_group = "adult" if age >= 22 else "child"

                                hashed_pw = hash_password(password_input.strip())

                                profile = {
                                    "username": username.strip(),
                                    "first_name": first_name.strip(),
                                    "last_name": last_name.strip() or None,
                                    "year_of_birth": year,
                                    "language": language,
                                    "location": location.strip() or None,
                                    "password": hashed_pw,
                                }

                                users[username] = profile
                                save_users(users)

                                st.session_state["role"] = "user"
                                st.session_state["user_name"] = first_name.strip()
                                st.session_state["age_group"] = age_group
                                st.session_state["user_profile"] = profile
                                # Create persistent session token
                                sessions = load_sessions()
                                token = secrets.token_urlsafe(16)
                                sessions[token] = {
                                    "role": "user",
                                    "username": username.strip(),
                                    "created_at": datetime.datetime.now().isoformat(),
                                }
                                save_sessions(sessions)
                                st.session_state["session_token"] = token

                                st.success(f"Signed up and logged in as user ({age_group} mode).")
                                st.rerun()
                    except ValueError:
                        st.error("Please enter birth year as numbers (YYYY).")

    st.stop()
# If logged in (i.e., we did not stop above), optionally show a gentle session-expiry reminder
token = st.session_state.get("session_token")
if token:
    try:
        sessions = load_sessions()
        sess = sessions.get(token)
        if sess and sess.get("created_at"):
            created_dt = datetime.datetime.fromisoformat(sess["created_at"])
            now_dt = datetime.datetime.now()
            minutes_used = (now_dt - created_dt).total_seconds() / 60.0
            if 30 <= minutes_used < SESSION_TTL_MINUTES:
                st.info(
                    "For your safety, this session will expire after 40 minutes. "
                    "If you are writing a long reflection, consider finishing and saving soon."
                )
    except Exception:
        pass
# ---------- SIDEBAR: OPTIONS ----------

with st.sidebar:
    st.header("Options")
    st.checkbox(
        "Generate cartoon illustration for each story",
        key="generate_image",
        help="Automatically creates ACK or Clay style images.",
    )

# ---------- TOP INFO + LOGIN BAR (LOGGED-IN ONLY) ----------

col_title, col_login = st.columns([4, 1])

with col_title:
    st.title("📚 Dharma Story Chat — Story Mode (All Books)")
    st.write("Stories come from **all** your uploaded books. Each answer shows which books were used.")

with col_login:
    role = st.session_state.get("role", "guest")
    user_name = st.session_state.get("user_name")
    age_group = st.session_state.get("age_group")

    if role == "admin":
        st.markdown("👑 **Admin**")
        if st.button("Logout", key="logout_button_admin"):
            # Remove persistent session
            token = st.session_state.get("session_token")
            if token:
                sessions = load_sessions()
                sessions.pop(token, None)
                save_sessions(sessions)
                st.session_state["session_token"] = None

            st.session_state["role"] = "guest"
            st.session_state["user_name"] = None
            st.session_state["age_group"] = None
            st.session_state["user_profile"] = {}
            st.rerun()

    elif role == "user":
        label = "🙂 User"
        if age_group == "child":
            label += " (Child mode)"
        elif age_group == "adult":
            label += " (Adult)"
        if user_name:
            label += f": {user_name}"
        st.markdown(label)

        if st.button("📜 Saved stories", key="history_toggle_button"):
            st.session_state["show_history_panel"] = not st.session_state.get("show_history_panel", False)

        if st.button("Logout", key="logout_button_user"):
            # Remove persistent session
            token = st.session_state.get("session_token")
            if token:
                sessions = load_sessions()
                sessions.pop(token, None)
                save_sessions(sessions)
                st.session_state["session_token"] = None

            st.session_state["role"] = "guest"
            st.session_state["user_name"] = None
            st.session_state["age_group"] = None
            st.session_state["user_profile"] = {}
            st.session_state["show_history_panel"] = False
            st.rerun()

# ---------- ADMIN-ONLY BOOK / UNREADABLE INFO ----------

role = st.session_state.get("role", "guest")
if role == "admin":
    admin_view = st.radio(
        "Admin panel:",
        ["Books & indexing", "Practice approval", "Guidance", "Internet search"],
        horizontal=True,
        key="admin_view_mode",
    )

    if admin_view == "Books & indexing":
        if st.button("🔄 Reindex books now", key="admin_reindex"):
            with st.spinner("Reindexing books from the 'books' folder..."):
                try:
                    result = subprocess.run(
                        ["python3", "prepare_data.py"],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    st.success("Reindexing finished successfully.")

                    if result.stdout:
                        st.text_area("Reindex log (stdout)", result.stdout, height=200)
                    if result.stderr:
                        st.text_area("Reindex log (stderr)", result.stderr, height=200)

                    st.cache_data.clear()
                    st.cache_resource.clear()
                except subprocess.CalledProcessError as e:
                    st.error("Reindexing failed. See log below.")
                    err_text = e.stderr or str(e)
                    st.text_area("Error log", err_text, height=200)

        unreadable = load_unreadable()
        if unreadable:
            st.warning("Some books could not be read completely (scanned or problematic):")
            for path, reason in unreadable.items():
                st.write(f"- `{os.path.basename(path)}` — {reason}")

        book_list = list_book_names()
        if book_list:
            with st.expander("Books currently available"):
                for b in book_list:
                    st.write("•", b)
        else:
            st.info("No books found yet in 'books/' folder.")

    elif admin_view == "Practice approval":
        st.subheader("Practice approval (mantra / meditation)")
        st.write(
            "From the uploaded dharmic texts, the app can suggest passages that feel "
            "suitable for gentle meditation or mantra remembrance. As admin, you can "
            "review and bless which of these become guided practices for seekers."
        )

        practice_scope = st.radio(
            "What would you like to review now?",
            ["Meditation", "Mantras", "Both"],
            horizontal=True,
            key="practice_scope_mode",
        )

        if practice_scope == "Meditation":
            kind_filter = "meditation"
        elif practice_scope == "Mantras":
            kind_filter = "mantra"
        else:
            kind_filter = None  # Both

        # Optional book filter: allow admin to restrict scanning to chosen books
        available_books = list_book_names()
        selected_books = st.multiselect(
            "Limit scan to specific books (optional):",
            options=available_books,
            default=[],
            help="If you leave this empty, all indexed books will be scanned.",
            key="practice_book_filter",
        )

        # Extra keywords: admin can guide what to look for (e.g. 'mudra, pranayama, japa')
        extra_keywords_str = st.text_input(
            "Extra keywords for scanning (optional, comma-separated)",
            key="practice_extra_keywords",
            help="Example: 'mudra, pranayama, japa, dharana'",
        )

        extra_keywords = []
        if extra_keywords_str.strip():
            extra_keywords = [w.strip() for w in extra_keywords_str.split(",") if w.strip()]

        if st.button("🔍 Scan books for new practice candidates", key="scan_practices"):
            with st.spinner("Scanning books for related passages..."):
                candidates = scan_practice_candidates_from_chroma(
                    kind_filter=kind_filter,
                    book_filter=selected_books if selected_books else None,
                    extra_keywords=extra_keywords,
                )
            st.success(f"Scan complete. Total candidates stored: {len(candidates)}")
        else:
            candidates = load_practice_candidates()

        # If admin selected specific books, restrict displayed candidates to those books
        if selected_books:
            selected_set = set(selected_books)
            filtered = []
            for c in candidates:
                src = c.get("source") or ""
                fname = os.path.basename(src) if src else ""
                if fname in selected_set:
                    filtered.append(c)
            candidates = filtered

        approved = load_approved_practices()

        if not candidates:
            st.info(
                "No possible practice passages have been collected yet. "
                "Use 'Scan books' to let the app suggest places where the texts "
                "speak about meditation or mantra remembrance."
            )
        else:
            st.markdown("### Pending candidates")
            any_pending = False
            approve_states = []

            for idx, cand in enumerate(candidates):
                if cand.get("approved"):
                    continue

                kind = cand.get("kind", "unknown")

                # Filter by chosen scope so admin can review one type at a time if desired.
                if kind_filter == "mantra" and kind != "mantra":
                    continue
                if kind_filter == "meditation" and kind != "meditation":
                    continue

                any_pending = True
                src = cand.get("source") or "unknown"
                text = cand.get("text") or ""

                label_kind = "MEDITATION" if kind == "meditation" else "MANTRA" if kind == "mantra" else kind.upper()
                with st.expander(f"[{label_kind}] from {os.path.basename(src)}", expanded=False):
                    st.markdown(f"<div class='source-text'>{text}</div>", unsafe_allow_html=True)
                    ck = st.checkbox(
                        "Approve this practice",
                        key=f"approve_cand_{idx}",
                    )
                    approve_states.append((idx, ck))

            if not any_pending:
                st.info("No unapproved candidates at the moment.")

            if approve_states and st.button("💾 Save approvals", key="save_practice_approvals"):
                # Load fresh copies to avoid mismatch if state changed.
                candidates = load_practice_candidates()
                approved = load_approved_practices()

                for idx, is_checked in approve_states:
                    if not is_checked:
                        continue
                    if idx < 0 or idx >= len(candidates):
                        continue
                    cand = candidates[idx]
                    if cand.get("approved"):
                        continue

                    kind = cand.get("kind", "unknown")
                    if kind not in ("mantra", "meditation"):
                        continue

                    # Mark candidate as approved and append to approved list.
                    cand["approved"] = True
                    practices_list = approved.get(kind) or []
                    practices_list.append(
                        {
                            "text": cand.get("text", ""),
                            "source": cand.get("source", ""),
                        }
                    )
                    approved[kind] = practices_list

                save_practice_candidates(candidates)
                save_approved_practices(approved)
                st.success("Selected practices have been approved and saved.")

    elif admin_view == "Guidance":
        st.subheader("Guided practices (manual)")
        st.write(
            "Here you can gently add your own meditation or mantra guidance. "
            "You may write a short passage and optionally attach an audio, image, or video file. "
            "Seekers will first see the text, then can listen or watch the guidance."
        )

        guidance_kind = st.radio(
            "What type of guidance would you like to add?",
            ["Meditation", "Mantra"],
            horizontal=True,
            key="guidance_kind_mode",
        )

        # Defaults so variables exist
        deity_name = ""
        age_group_code = "both"
        level_number = 1
        guidance_text = ""
        mantra_lines = ""
        mantra_desc = ""

        if guidance_kind == "Meditation":
            kind_key = "meditation"
            st.markdown("**Meditation guidance text:**")
            guidance_text = st.text_area(
                "Meditation guidance (this will appear before any audio/image/video):",
                key="guidance_text_input",
                height=160,
            )
        else:
            kind_key = "mantra"

            st.markdown("**Mantra targeting (for users):**")

            # Load existing deities from approved mantra practices (if any)
            existing_deities = []
            try:
                approved_existing = load_approved_practices()
                mantra_existing = approved_existing.get("mantra", [])
                deity_set = set()
                for item in mantra_existing:
                    dname = (item.get("deity") or "").strip()
                    if dname:
                        deity_set.add(dname)
                existing_deities = sorted(deity_set, key=str.lower)
            except Exception:
                existing_deities = []

            deity_choice_mode = "Type new name"
            selected_existing_deity = None

            if existing_deities:
                deity_choice_mode = st.radio(
                    "How would you like to choose deity?",
                    ["Use existing deity", "Type new name"],
                    horizontal=True,
                    key="deity_choice_mode",
                )
                if deity_choice_mode == "Use existing deity":
                    selected_existing_deity = st.selectbox(
                        "Existing deities:",
                        existing_deities,
                        key="existing_deity_select",
                    )

            if deity_choice_mode == "Use existing deity" and selected_existing_deity:
                deity_name = selected_existing_deity
                st.info(f"Adding mantra for deity: {deity_name}")
            else:
                deity_name = st.text_input(
                    "Deity / God name for this mantra (e.g. Shiva, Krishna, Devi)",
                    key="guidance_deity_input",
                )

            age_choice = st.radio(
                "Who is this mantra best suited for?",
                ["All ages", "Children", "Adults"],
                horizontal=True,
                key="guidance_age_group_choice",
            )
            if age_choice == "Children":
                age_group_code = "child"
            elif age_choice == "Adults":
                age_group_code = "adult"
            else:
                age_group_code = "both"

            level_number = st.number_input(
                "Suggested mantra level (1 = beginner, 2 = deeper, etc.)",
                min_value=1,
                max_value=20,
                value=1,
                step=1,
                key="guidance_level_number",
            )

            st.markdown("**Mantra text (exactly as chanted):**")
            mantra_lines = st.text_area(
                "Mantra lines (line breaks will be preserved exactly for users):",
                key="mantra_text_input",
                height=120,
            )

            mantra_desc = st.text_area(
                "Description / meaning / practice guidance (optional but recommended):",
                key="mantra_desc_input",
                height=160,
            )

        # 🔊 Audio uploader (single definition)
        uploaded_audio = st.file_uploader(
            "Optional: upload an audio file for this guidance",
            type=["mp3", "wav", "m4a", "ogg"],
            key="guidance_audio_uploader",
        )

        # 🖼 Image uploader (single definition)
        uploaded_image = st.file_uploader(
            "Optional: upload an image for this guidance",
            type=["png", "jpg", "jpeg", "webp"],
            key="guidance_image_uploader",
        )

        # 🎥 Video uploader (single definition)
        uploaded_video = st.file_uploader(
            "Optional: upload a video for this guidance",
            type=["mp4", "mov", "m4v", "webm", "mpeg4"],
            key="guidance_video_uploader",
        )

        if st.button("Save guidance", key="guidance_save_button"):
            # Basic validation
            if kind_key == "meditation":
                if not guidance_text.strip():
                    st.error("Please write a short guidance passage before saving (especially if you include media).")
                    st.stop()
            else:
                if not mantra_lines.strip():
                    st.error("Please enter the mantra text (even if the description is short).")
                    st.stop()
                if not deity_name.strip():
                    st.error("Please enter a deity / god name for this mantra.")
                    st.stop()

            # ---- Save audio ----
            saved_audio_path = None
            original_name = None

            if uploaded_audio is not None:
                try:
                    original_name = uploaded_audio.name
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_name = original_name.replace(" ", "_")
                    filename = f"{kind_key}_{ts}_{safe_name}"
                    saved_audio_path = os.path.join(GUIDANCE_AUDIO_DIR, filename)
                    with open(saved_audio_path, "wb") as f:
                        f.write(uploaded_audio.getbuffer())
                except Exception as e:
                    st.error(f"Could not save audio file: {e}")
                    saved_audio_path = None

            # ---- Save image ----
            saved_image_path = None
            image_original_name = None
            if uploaded_image is not None:
                try:
                    image_original_name = uploaded_image.name
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_name_img = image_original_name.replace(" ", "_")
                    img_filename = f"{kind_key}_img_{ts}_{safe_name_img}"
                    saved_image_path = os.path.join(GUIDANCE_MEDIA_DIR, img_filename)
                    with open(saved_image_path, "wb") as f:
                        f.write(uploaded_image.getbuffer())
                except Exception as e:
                    st.error(f"Could not save image file: {e}")
                    saved_image_path = None

            # ---- Save video ----
            saved_video_path = None
            video_original_name = None
            if uploaded_video is not None:
                try:
                    video_original_name = uploaded_video.name
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_name_vid = video_original_name.replace(" ", "_")
                    vid_filename = f"{kind_key}_vid_{ts}_{safe_name_vid}"
                    saved_video_path = os.path.join(GUIDANCE_MEDIA_DIR, vid_filename)
                    with open(saved_video_path, "wb") as f:
                        f.write(uploaded_video.getbuffer())
                except Exception as e:
                    st.error(f"Could not save video file: {e}")
                    saved_video_path = None

            # ---- Store entry in approved_practices ----
            approved = load_approved_practices()
            practices_list = approved.get(kind_key) or []

            entry = {
                "source": "manual-guidance",
            }

            if kind_key == "meditation":
                entry["text"] = guidance_text.strip()
            else:
                entry["mantra_text"] = mantra_lines.rstrip()
                entry["text"] = mantra_desc.strip()
                entry["deity"] = deity_name.strip()
                entry["age_group"] = age_group_code  # "child", "adult", or "both"
                entry["level"] = int(level_number)

            if saved_audio_path:
                entry["audio_path"] = saved_audio_path
                if original_name:
                    entry["audio_original_name"] = original_name

            if saved_image_path:
                entry["image_path"] = saved_image_path
                if image_original_name:
                    entry["image_original_name"] = image_original_name

            if saved_video_path:
                entry["video_path"] = saved_video_path
                if video_original_name:
                    entry["video_original_name"] = video_original_name

            practices_list.append(entry)
            approved[kind_key] = practices_list
            save_approved_practices(approved)

            st.success("Your guidance has been saved and will appear in the journey levels.")

        st.markdown("---")
        st.subheader("Existing mantra deities")

        # Show existing deities, so admin can see what already exists
        approved_all = load_approved_practices()
        mantra_existing_all = approved_all.get("mantra", []) or []

        deity_map = {}
        for idx, item in enumerate(mantra_existing_all):
            dname = (item.get("deity") or "General").strip()
            if not dname:
                dname = "General"
            deity_map.setdefault(dname, []).append((idx, item))

        if not deity_map:
            st.write("No mantra deities configured yet.")
        else:
            for dname, items in sorted(deity_map.items(), key=lambda x: x[0].lower()):
                with st.expander(f"Deity: {dname} ({len(items)} mantra entries)", expanded=False):
                    for idx, item in items:
                        level = item.get("level")
                        label = f"Level {level}" if level is not None else f"Entry {idx+1}"
                        st.markdown(f"**{label}**")
                        preview = item.get("mantra_text") or item.get("text") or ""
                        if len(preview) > 200:
                            preview = preview[:200] + " ..."
                        st.markdown(
                            f"<div class='source-text'>{preview}</div>",
                            unsafe_allow_html=True,
                        )
# end of Guidance block
    elif admin_view == "Internet search":
        st.subheader("🌐 Mantra & meditation suggestions (admin review)")
        st.write(
            "Use this space to ask the model for **mantras and meditation ideas** for any deity and level. "
            "It will offer a variety of possibilities (as if searching wider traditions), and you remain the "
            "final approval before anything reaches the users. Save only what you recognise and are happy to bless."
        )

        deity_name = st.text_input(
            "Deity / God name (e.g. Shiva, Krishna, Devi)",
            key="online_deity_name",
        )

        scope_choice = st.radio(
            "What would you like to search for?",
            ["Mantras", "Meditations", "Both"],
            horizontal=True,
            key="online_scope_choice",
        )

        level_choice = st.selectbox(
            "Which level are you focusing on?",
            ["Beginner", "Intermediate", "Deeper"],
            index=0,
            key="online_level_choice",
        )

        if st.button("🌐 Search online suggestions", key="online_search_button"):
            if not deity_name.strip():
                st.error("Please enter a deity / god name first.")
            else:
                with st.spinner("Asking the model for safe, traditional suggestions..."):
                    results = fetch_online_practices(
                        deity_name=deity_name,
                        scope=scope_choice,
                        level_label=level_choice,
                    )
                st.session_state["online_search_results"] = results
                if results:
                    st.success(f"Received {len(results)} suggestions. Review them below.")
                else:
                    st.warning("No suggestions were returned. Try adjusting scope or deity name.")

        results = st.session_state.get("online_search_results") or []
        if results:
            st.markdown("### Suggestions")
            add_flags = []

            for idx, p in enumerate(results):
                kind = (p.get("kind") or "").lower()
                kind_label = "MANTRA" if kind == "mantra" else "MEDITATION"
                title = p.get("title") or "Untitled practice"
                deity_p = p.get("deity") or deity_name or ""
                level_p = p.get("level") or level_choice
                mantra_text = p.get("mantra_text") or ""
                instructions = p.get("instructions") or ""
                source_hint = p.get("source_hint") or ""

                header = f"[{kind_label}] {title} — {deity_p} ({level_p})"
                with st.expander(header, expanded=False):
                    if mantra_text:
                        safe_mantra = (
                            mantra_text.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                        )
                        st.markdown(
                            f"<div class='mantra-box'>{safe_mantra}</div>",
                            unsafe_allow_html=True,
                        )
                    if instructions:
                        safe_instr = (
                            instructions.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                        )
                        st.markdown("**Guidance / instructions:**")
                        st.markdown(
                            f"<div class='answer-text'>{safe_instr}</div>",
                            unsafe_allow_html=True,
                        )
                    if source_hint:
                        st.markdown(f"_Source hint: {source_hint}_")

                    ck = st.checkbox(
                        "Add this suggestion to practice candidates",
                        key=f"online_add_{idx}",
                    )
                    add_flags.append((idx, ck))

            if add_flags and st.button("💾 Save selected suggestions", key="online_save_suggestions"):
                candidates = load_practice_candidates()
                # Use deity_name and level_choice as fallback defaults
                for idx, is_checked in add_flags:
                    if not is_checked:
                        continue
                    if idx < 0 or idx >= len(results):
                        continue
                    p = results[idx]
                    kind = (p.get("kind") or "mantra").lower()
                    title = p.get("title") or ""
                    deity_p = (p.get("deity") or deity_name or "").strip()
                    level_p = (p.get("level") or level_choice).strip()
                    mantra_text = p.get("mantra_text") or ""
                    instructions = p.get("instructions") or ""
                    source_hint = p.get("source_hint") or "online suggestion"

                    lines = []
                    if title:
                        lines.append(f"{title} ({level_p})")
                    if mantra_text:
                        lines.append(mantra_text)
                    if instructions:
                        lines.append(instructions)
                    if source_hint:
                        lines.append(f"[Source hint: {source_hint}]")
                    combined_text = "\n\n".join(lines)

                    cand = {
                        "kind": kind,
                        "source": f"online:{deity_p or 'unknown'}",
                        "text": combined_text,
                        "approved": False,
                        "deity": deity_p,
                        "level": level_p.lower(),
                    }
                    candidates.append(cand)

                save_practice_candidates(candidates)
                st.success(
                    "Selected suggestions have been stored as practice candidates. "
                    "You can now review and give final approval under 'Practice approval'."
                )
        else:
            st.info("No online suggestions yet. Enter a deity name above and click search.")

# ---------- MAIN USER NAVIGATION (HOME / MEDITATION / MANTRA) ----------

if st.session_state.get("role") == "user":
    main_mode = st.radio(
        "Where would you like to go?",
        ["Home", "Meditation journey", "Mantra chanting journey", "My Journey"],
        horizontal=True,
        key="main_nav_mode",
    )
else:
    main_mode = "Home"

# USER SAVED STORIES PANEL (like ChatGPT, but only favourites)

if (
    st.session_state.get("role") == "user"
    and st.session_state.get("show_history_panel", False)
    and main_mode == "Home"
):
    username = get_current_username()
    favs_all = load_favourites()
    user_favs = favs_all.get(username, []) if username else []

    with st.expander("⭐ Your saved stories", expanded=True):
        if not user_favs:
            st.write("You have not saved any stories yet. Tap '⭐ Save this story' under a story to add it here.")
        else:
            for i, item in enumerate(reversed(user_favs), start=1):
                ts = item.get("timestamp", "")
                books_used = item.get("books_used") or []
                title_line = f"Story {i}"
                if ts:
                    title_line += f" — saved at {ts}"
                st.markdown(f"**{title_line}**")
                if books_used:
                    st.markdown(f"_Books: {', '.join(sorted(books_used))}_")
                preview = item.get("content", "")
                if len(preview) > 1200:
                    preview = preview[:1200] + " ..."
                st.markdown(f"<div class='answer-text'>{preview}</div>", unsafe_allow_html=True)
                st.markdown("---")

st.markdown("---")

# ---------- MAIN CONTENT: HOME CHAT OR JOURNEYS ----------

if "book_list" not in locals():
    book_list = list_book_names()


def get_daily_focus(age_group):
    """Return a short line describing today's spiritual focus."""
    themes = [
        "Remembering one divine quality again and again.",
        "Bringing kindness into one small action.",
        "Watching the breath for a few quiet moments.",
        "Offering worries into an inner flame of trust.",
        "Seeing every being as carrying a spark of the Divine.",
    ]
    today = datetime.date.today()
    idx = today.toordinal()
    line = themes[idx % len(themes)]
    if age_group == "child":
        child_variants = [
            "Remember one good thing about God again and again today.",
            "Try one extra kind action today.",
            "Close your eyes and feel 5 soft breaths.",
            "Give one worry to God in your heart.",
            "Look at people and think: 'There is a little light inside them.'",
        ]
        line = child_variants[idx % len(child_variants)]
    return line


def get_micro_practice(age_group):
    """Return a tiny, practical sadhana suggestion for the day."""
    adult_items = [
        "Before checking your phone in the morning, place your hand on your heart and remember your chosen deity once.",
        "Take 3 conscious breaths before starting any important task today.",
        "When irritation arises, pause for one breath and silently repeat a divine name once.",
        "Before sleep, mentally offer the best and worst moments of your day into a small inner flame.",
        "Choose one action today and consciously dedicate it as a small offering.",
    ]
    child_items = [
        "Say thank you to God once today in your own words.",
        "Take 3 slow breaths and imagine light in your heart.",
        "When you feel angry, count to 5 and think of your favourite form of God.",
        "Before sleep, tell the Divine one thing you liked today.",
        "Share one toy or snack and imagine the Divine smiling.",
    ]
    today = datetime.date.today()
    idx = today.toordinal()
    if age_group == "child":
        return child_items[idx % len(child_items)]
    else:
        return adult_items[idx % len(adult_items)]


if main_mode == "Home":
    # Helper to run a full Q&amp;A cycle from a preset question (for mood buttons etc.)
    def run_question_flow(question_text: str):
        if not question_text:
            return
        st.session_state["messages"].append({"role": "user", "content": question_text})
        passages, metas = retrieve_passages(question_text)
        answer = answer_question(
            question_text,
            passages,
            book_list,
            history_messages=st.session_state["messages"],
            answer_length=st.session_state.get("answer_length", "Medium"),
        )
        books_used = set()
        for m in metas:
            src = m.get("source")
            if src:
                books_used.add(os.path.basename(src))

        image_url = None
        style_used = None
        if st.session_state.get("generate_image"):
            image_url, style_used = generate_styled_image(question_text, answer)

        st.session_state["messages"].append(
            {
                "role": "assistant",
                "content": answer,
                "image_url": image_url,
                "style": style_used,
                "passages": passages,
                "metas": metas,
                "books_used": list(books_used),
            }
        )
        st.rerun()

    # Daily reflection + focus + micro-practice at the top of Home
    age_group = st.session_state.get("age_group")
    try:
        daily_line = get_daily_reflection(age_group)
        daily_focus = get_daily_focus(age_group)
        micro_practice = get_micro_practice(age_group)
    except Exception:
        daily_line = None
        daily_focus = None
        micro_practice = None

    if daily_line:
        st.markdown("### 🌅 Today's reflection")
        st.markdown(
            f"<div class='daily-reflection'>{daily_line}</div>",
            unsafe_allow_html=True,
        )
    if daily_focus:
        st.markdown("#### 🎯 Today's focus")
        st.write(daily_focus)
    if micro_practice:
        st.markdown("#### 🕯️ Tiny practice for today")
        st.write(micro_practice)

    # Simple navigation buttons
    if st.session_state.get("role") == "user":
        st.markdown("### Quick navigation")
        nav_col1, nav_col2, nav_col3 = st.columns(3)
        with nav_col1:
            if st.button("🏠 Ask & Learn", key="nav_home_btn"):
                st.session_state["main_nav_mode"] = "Home"
                st.rerun()
        with nav_col2:
            if st.button("🧘 Meditation journey", key="nav_med_btn"):
                st.session_state["main_nav_mode"] = "Meditation journey"
                st.rerun()
        with nav_col3:
            if st.button("📿 Mantra journey", key="nav_mantra_btn"):
                st.session_state["main_nav_mode"] = "Mantra chanting journey"
                st.rerun()

        st.markdown("---")

    if st.session_state.get("role") == "user":
        st.markdown("### How are you feeling today?")
        mcol1, mcol2, mcol3, mcol4 = st.columns(4)
        with mcol1:
            if st.button("😟 I feel anxious", key="mood_anxious"):
                run_question_flow(
                    "I feel anxious. Please tell me a gentle dharmic story or guidance to calm my mind from the uploaded books."
                )
        with mcol2:
            if st.button("😞 Low energy", key="mood_low_energy"):
                run_question_flow(
                    "My energy is low. From these books, give me a short story or guidance that brings strength and hope."
                )
        with mcol3:
            if st.button("💪 Need courage", key="mood_courage"):
                run_question_flow(
                    "I need courage for a challenge. Tell me a story or teaching about courage from these dharmic books."
                )
        with mcol4:
            if st.button("❤️ More devotion", key="mood_bhakti"):
                run_question_flow(
                    "I want to feel more devotion and love for the Divine. Share a story or guidance about bhakti from these books."
                )

        st.markdown("---")

    # Render chat history
    for idx, msg in enumerate(st.session_state["messages"]):
        role = msg["role"]
        content = msg["content"]

        if role == "user":
            with st.chat_message("user"):
                st.markdown(content)
        else:
            with st.chat_message("assistant"):
                st.markdown(
                    f"<div class='answer-text'>{content}</div>",
                    unsafe_allow_html=True,
                )

                books_used = msg.get("books_used", [])
                if books_used:
                    ref_text = ", ".join(sorted(books_used))
                    st.markdown(f"**References (books used):** _{ref_text}_")

                if msg.get("image_url"):
                    st.image(
                        msg["image_url"],
                        caption=f"Illustration (style: {msg.get('style', '').upper()})",
                        use_column_width=True,
                    )

                if msg.get("passages") and msg.get("metas"):
                    st.markdown("**Passages used from your books:**")
                    for i, (p, m) in enumerate(zip(msg["passages"], msg["metas"])):
                        src = m.get("source", "unknown")
                        fname = os.path.basename(src) if src else "unknown"
                        with st.expander(f"Passage {i+1} — Source file: {fname}"):
                            st.markdown(
                                f"<div class='source-text'>{p}</div>",
                                unsafe_allow_html=True,
                            )

                # Save story button (for logged-in users) on Home only
                if st.session_state.get("role") == "user":
                    username = get_current_username()
                    if username:
                        fav_button_key = f"save_story_{idx}"
                        if st.button("⭐ Save this story", key=fav_button_key):
                            favs_all = load_favourites()
                            user_favs = favs_all.get(username, [])
                            # Avoid saving exact duplicates (same content and books_used)
                            if not any(
                                f.get("content") == msg["content"]
                                and f.get("books_used") == msg.get("books_used", [])
                                for f in user_favs
                            ):
                                user_favs.append(
                                    {
                                        "content": msg["content"],
                                        "books_used": msg.get("books_used", []),
                                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                                    }
                                )
                                favs_all[username] = user_favs
                                save_favourites(favs_all)
                                st.success("Story saved to your favourites.")

    # ---------- CHAT INPUT ----------
    user_input = st.chat_input("Ask for a story (e.g. 'Tell me a story about Shiva's compassion')...")

    if user_input:
        st.session_state["messages"].append(
            {"role": "user", "content": user_input}
        )

        passages, metas = retrieve_passages(user_input)

        answer = answer_question(
            user_input,
            passages,
            book_list,
            history_messages=st.session_state["messages"],
            answer_length=st.session_state.get("answer_length", "Medium"),
        )

        books_used = set()
        for m in metas:
            src = m.get("source")
            if src:
                books_used.add(os.path.basename(src))

        image_url = None
        style_used = None
        if st.session_state["generate_image"]:
            image_url, style_used = generate_styled_image(user_input, answer)

        st.session_state["messages"].append(
            {
                "role": "assistant",
                "content": answer,
                "image_url": image_url,
                "style": style_used,
                "passages": passages,
                "metas": metas,
                "books_used": list(books_used),
            }
        )

        st.rerun()

elif main_mode == "Meditation journey":
    st.header("🧘 Meditation journey")

    if st.session_state.get("role") != "user":
        st.info("Meditation levels are available for logged-in users only.")
    else:
        approved = load_approved_practices()
        med_practices = approved.get("meditation", [])

        profile = st.session_state.get("user_profile") or {}
        med_level = profile.get("meditation_level", 1)

        if not med_practices:
            st.info(
                "No approved meditation practices are available yet. "
                "Ask the admin to approve some meditation passages from the books."
            )
        else:
            max_level = min(20, len(med_practices))
            if med_level > max_level:
                st.success("You have completed all available meditation levels.")
                st.write(f"Current meditation level: {med_level}")
            else:
                practice = med_practices[med_level - 1]
                src = practice.get("source") or "unknown"

                st.subheader(f"Meditation Level {med_level} of {max_level}")
                st.markdown(f"_Source: {os.path.basename(src)}_")
                # Simple progress bar based on current level
                st.progress((med_level - 1) / max_level)
                st.markdown(
                    f"<div class='answer-text'>{practice.get('text', '')}</div>",
                    unsafe_allow_html=True,
                )
                # Render audio if present
                audio_path = practice.get("audio_path")
                if audio_path and os.path.exists(audio_path):
                    st.markdown("**Listen to this guided meditation:**")
                    st.audio(audio_path)

                reflection = st.text_area(
                    "What did you feel or notice in this practice?",
                    key=f"med_reflection_{med_level}",
                )

                if st.button("Mark this level as completed", key=f"med_complete_{med_level}"):
                    # Store reflection (if any) into user profile.
                    med_reflections = profile.get("meditation_reflections") or {}
                    if reflection.strip():
                        med_reflections[str(med_level)] = reflection.strip()
                    profile["meditation_reflections"] = med_reflections

                    # Increment level and save to user profile.
                    profile["meditation_level"] = med_level + 1
                    st.session_state["user_profile"] = profile

                    username = profile.get("username")
                    if username:
                        users = load_users()
                        users[username] = profile
                        save_users(users)

                    st.success("Meditation level completed. Next time you'll see the next level.")
                    st.rerun()

elif main_mode == "Mantra chanting journey":
    st.header("📿 Mantra chanting journey")

    if st.session_state.get("role") != "user":
        st.info("Mantra levels are available for logged-in users only.")
    else:
        approved = load_approved_practices()
        mantra_practices = approved.get("mantra", [])

        profile = st.session_state.get("user_profile") or {}

        if not mantra_practices:
            st.info(
                "No approved mantra practices are available yet. "
                "Ask the admin to approve some mantra-related passages from the books or Guidance panel."
            )
        else:
            # Build list of deities from stored mantra practices
            deity_names = set()
            for p in mantra_practices:
                deity = (p.get("deity") or "General").strip()
                if deity:
                    deity_names.add(deity)
            if not deity_names:
                deity_names.add("General")

            deity_list = sorted(deity_names, key=lambda x: x.lower())

            # Remember last chosen deity in session
            default_deity = st.session_state.get("selected_mantra_deity")
            if default_deity not in deity_list:
                default_deity = deity_list[0]

            selected_deity = st.selectbox(
                "Choose deity for today's chanting",
                deity_list,
                index=deity_list.index(default_deity),
                key="selected_mantra_deity",
            )

            # Filter practices by selected deity and user age group
            user_age_group = st.session_state.get("age_group")

            def _matches_age(p, age_group):
                meta = p.get("age_group") or "both"
                if age_group is None:
                    return True
                if meta == "both":
                    return True
                return meta == age_group

            deity_practices = [
                p for p in mantra_practices
                if (p.get("deity") or "General").strip() == selected_deity
                and _matches_age(p, user_age_group)
            ]

            if not deity_practices:
                st.info(
                    "No mantra guidance is configured yet for this deity and age group. "
                    "Ask the admin to add some in the Guidance panel."
                )
            else:
                # Determine available levels for this deity
                levels_available = sorted(
                    {int(p.get("level", 1)) for p in deity_practices}
                )
                if not levels_available:
                    levels_available = [1]

                # Per-deity progress for this user
                mantra_progress = profile.get("mantra_progress") or {}
                current_level = int(mantra_progress.get(selected_deity, 1))

                max_level = max(levels_available)
                # If current level is beyond known levels, mark as complete
                if current_level > max_level:
                    st.success(
                        f"You have completed all configured mantra levels for {selected_deity}."
                    )
                    st.write(f"Current level for {selected_deity}: {current_level}")
                else:
                    # If current_level not present, fall back to nearest available
                    if current_level not in levels_available:
                        current_level = levels_available[0]
                        mantra_progress[selected_deity] = current_level
                        profile["mantra_progress"] = mantra_progress
                        st.session_state["user_profile"] = profile
                        username = profile.get("username")
                        if username:
                            users = load_users()
                            users[username] = profile
                            save_users(users)

                    # Select the first practice for this level
                    level_practices = [
                        p for p in deity_practices
                        if int(p.get("level", 1)) == current_level
                    ]
                    practice = level_practices[0] if level_practices else deity_practices[0]

                    src = practice.get("source") or "unknown"

                    st.subheader(f"{selected_deity} mantra — Level {current_level} of {max_level}")
                    st.markdown(f"_Source: {os.path.basename(src)}_")

                    # Simple progress bar based on index of current_level in the list
                    try:
                        idx = levels_available.index(current_level)
                        progress_val = idx / max(1, len(levels_available) - 1)
                    except ValueError:
                        progress_val = 0.0
                    st.progress(progress_val)

                    # Show mantra text exactly as admin typed it (line breaks preserved)
                    raw_mantra = practice.get("mantra_text") or practice.get("text") or ""
                    # Basic HTML escaping for safety
                    safe_mantra = (
                        raw_mantra.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                    )
                    st.markdown(
                        f"<div class='mantra-box'>{safe_mantra}</div>",
                        unsafe_allow_html=True,
                    )

                    # Optional description / meaning below
                    if practice.get("mantra_text"):
                        desc_text = practice.get("text", "")
                    else:
                        # Older entries might only have 'text'
                        desc_text = ""

                    if desc_text:
                        safe_desc = (
                            desc_text.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                        )
                        st.markdown("**Meaning / guidance:**")
                        st.markdown(
                            f"<div class='answer-text'>{safe_desc}</div>",
                            unsafe_allow_html=True,
                        )

                    # Render audio if present
                    audio_path = practice.get("audio_path")
                    if audio_path and os.path.exists(audio_path):
                        st.markdown("**Listen to this mantra guidance:**")
                        st.audio(audio_path)
                                        # Render image if present
                    image_path = practice.get("image_path")
                    if image_path and os.path.exists(image_path):
                        st.markdown("**Sacred image for this mantra:**")
                        st.image(image_path, use_column_width=True)

                    # Render video if present
                    video_path = practice.get("video_path")
                    if video_path and os.path.exists(video_path):
                        st.markdown("**Video guidance for this mantra:**")
                        st.video(video_path)

                    reflection = st.text_area(
                        "What did you feel or notice while chanting or remembering this?",
                        key=f"mantra_reflection_{selected_deity}_{current_level}",
                    )

                    if st.button("Mark this level as completed", key=f"mantra_complete_{selected_deity}_{current_level}"):
                        # Store reflection (if any) into user profile.
                        mantra_reflections = profile.get("mantra_reflections") or {}
                        if reflection.strip():
                            label = f"{selected_deity} – Level {current_level}"
                            mantra_reflections[label] = reflection.strip()
                        profile["mantra_reflections"] = mantra_reflections

                        # Update per-deity progress and save.
                        mantra_progress = profile.get("mantra_progress") or {}
                        mantra_progress[selected_deity] = current_level + 1
                        profile["mantra_progress"] = mantra_progress
                        st.session_state["user_profile"] = profile

                        username = profile.get("username")
                        if username:
                            users = load_users()
                            users[username] = profile
                            save_users(users)

                        st.success("Mantra level completed. Next time you'll see the next level for this deity.")
                        st.rerun()

elif main_mode == "My Journey":
    st.header("🛤️ My Journey")

    if st.session_state.get("role") != "user":
        st.info("Your journey view is available for logged-in users only.")
    else:
        profile = st.session_state.get("user_profile") or {}
        username = profile.get("username")

        # Meditation & mantra reflections
        med_refl = profile.get("meditation_reflections") or {}
        mantra_refl = profile.get("mantra_reflections") or {}

        # Simple sadhana summary
        med_level_done = len(med_refl) if med_refl else 0
        mantra_levels_done = len(mantra_refl) if mantra_refl else 0

        # Saved stories
        favs_all = load_favourites()
        user_favs = favs_all.get(username, []) if username else []
        saved_story_count = len(user_favs)

        # ----- BADGES -----
        badges = []
        if med_level_done >= 1:
            badges.append("🧘 Started meditation journey")
        if med_level_done >= 3:
            badges.append("🌿 3+ meditation reflections")
        if mantra_levels_done >= 3:
            badges.append("📿 3+ mantra reflections")
        if saved_story_count >= 5:
            badges.append("⭐ 5+ stories saved")
        if saved_story_count >= 10:
            badges.append("🌟 Story lover (10+ saved stories)")

        st.subheader("📊 Sadhana overview")
        st.write(f"Meditation levels with reflections: **{med_level_done}**")
        st.write(f"Mantra stages with reflections: **{mantra_levels_done}**")
        st.write(f"Stories saved: **{saved_story_count}**")

        if badges:
            st.markdown("#### 🌼 Blessing milestones")
            for b in badges:
                st.write("- " + b)

        st.markdown("---")

        # ----- SIMPLE TIMELINE -----
        st.subheader("🕰️ Journey timeline")

        timeline_entries = []

        # From meditation reflections
        for lvl_str, text in med_refl.items():
            timeline_entries.append({
                "when": None,
                "label": f"Meditation level {lvl_str} reflection",
                "type": "meditation",
            })

        # From mantra reflections (keys may be "1" or "Shiva – Level 1")
        for key, text in mantra_refl.items():
            timeline_entries.append({
                "when": None,
                "label": f"Mantra reflection – {key}",
                "type": "mantra",
            })

        # From saved stories
        for item in user_favs:
            ts = item.get("timestamp")
            label = "Saved a story"
            if ts:
                label = f"Saved a story ({ts})"
            timeline_entries.append({
                "when": ts,
                "label": label,
                "type": "story",
            })

        # Sort by timestamp string if available, else leave order
        def _sort_key(e):
            return e["when"] or ""
        timeline_entries = sorted(timeline_entries, key=_sort_key)

        if not timeline_entries:
            st.write("Your journey timeline will grow as you meditate, chant, and save stories.")
        else:
            for e in timeline_entries:
                bullet = "•"
                if e["type"] == "meditation":
                    bullet = "🧘"
                elif e["type"] == "mantra":
                    bullet = "📿"
                elif e["type"] == "story":
                    bullet = "⭐"
                if e["when"]:
                    st.write(f"{bullet} {e['label']}")
                else:
                    st.write(f"{bullet} {e['label']}")

        st.markdown("---")

        # ----- REFLECTIONS COLUMN VIEW -----
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🧘 Meditation reflections")
            if not med_refl:
                st.write("No meditation reflections saved yet.")
            else:
                for lvl_str in sorted(med_refl.keys(), key=lambda x: int(x)):
                    st.markdown(f"**Level {lvl_str}**")
                    st.markdown(
                        f"<div class='source-text'>{med_refl[lvl_str]}</div>",
                        unsafe_allow_html=True,
                    )

        with col2:
            st.subheader("📿 Mantra reflections")
            if not mantra_refl:
                st.write("No mantra reflections saved yet.")
            else:
                for key in sorted(mantra_refl.keys()):
                    label = key
                    st.markdown(f"**{label}**")
                    st.markdown(
                        f"<div class='source-text'>{mantra_refl[key]}</div>",
                        unsafe_allow_html=True,
                    )

        st.markdown("---")
        st.subheader("⭐ Saved stories")

        if not user_favs:
            st.write("You have not saved any stories yet.")
        else:
            for i, item in enumerate(reversed(user_favs), start=1):
                ts = item.get("timestamp", "")
                books_used = item.get("books_used") or []
                title_line = f"Story {i}"
                if ts:
                    title_line += f" — saved at {ts}"
                st.markdown(f"**{title_line}**")
                if books_used:
                    st.markdown(f"_Books: {', '.join(sorted(books_used))}_")
                preview = item.get("content", "")
                if len(preview) > 1600:
                    preview = preview[:1600] + " ..."
                st.markdown(
                    f"<div class='answer-text'>{preview}</div>",
                    unsafe_allow_html=True,
                )
                st.markdown("---")
                # ---------- FOOTER: GENTLE DISCLAIMER ----------

st.markdown("---")
st.markdown(
    """
<small>
This app shares dharmic stories and guidance based on uploaded texts.  
It is meant to gently support your spiritual journey, not replace a living teacher,
doctor, or mental-health professional.  
If you feel very distressed or unsafe, please seek proper help and speak to someone you trust.
</small>
    """,
    unsafe_allow_html=True,
)