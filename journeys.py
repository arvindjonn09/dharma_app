import streamlit as st
from ui import render_mantra_html, render_answer_html
from database import load_approved_practices


def render_meditation_journey(user_profile: dict):
    st.header("🧘 Meditation journey")
    st.write(
        "This section will guide you through gentle, level-based meditation practices "
        "approved by the admin, based on your age group."
    )

    age_group = user_profile.get("age_group") or user_profile.get("age_group_code")

    approved = load_approved_practices()
    meditations = approved.get("meditation", []) or []

    if not meditations:
        st.info("No meditation practices have been approved yet.")
        return

    for i, item in enumerate(meditations, start=1):
        text = item.get("text", "")
        src = item.get("source", "")
        with st.expander(f"Meditation {i} — from {src or 'manual'}", expanded=(i == 1)):
            render_answer_html(text)


def render_mantra_journey(user_profile: dict):
    st.header("📿 Mantra chanting journey")
    st.write(
        "Here you can explore mantras that have been approved by the admin. "
        "Over time, we can make this more level-based and interactive."
    )

    approved = load_approved_practices()
    mantras = approved.get("mantra", []) or []

    if not mantras:
        st.info("No mantra practices have been approved yet.")
        return

    for i, item in enumerate(mantras, start=1):
        deity = item.get("deity") or "General"
        level = item.get("level")
        label = f"{deity}"
        if level:
            label += f" (Level {level})"
        with st.expander(label, expanded=(i == 1)):
            mantra_text = item.get("mantra_text") or item.get("text", "")
            render_mantra_html(mantra_text)


def render_my_journey(user_profile: dict):
    st.header("🪔 My spiritual journey")
    st.write(
        "This page will, in future, show your progress across meditation and mantra levels.\n\n"
        "For now, it simply acknowledges that you are walking a sincere path 🙏."
    )