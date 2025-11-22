import streamlit as st


def apply_global_css():
    """Inject global CSS styles for the Dharma app."""
    st.markdown(
        """
        <style>
        body {
            background: radial-gradient(circle at top, #2b2b4b 0, #101018 45%, #050508 100%);
            color: #f5f5f5;
        }
        .answer-text {
            font-size: 1.05rem;
            line-height: 1.6;
            color: #f5f5f5;
            border-left: 4px solid #e0b45a;
            padding-left: 1rem;
            margin-bottom: 1rem;
            background-color: rgba(255, 255, 255, 0.03);
        }
        .source-text {
            font-size: 0.8rem;
            line-height: 1.4;
            color: #f0f0f0;
            background-color: #3a3120;
            padding: 0.75rem 0.9rem;
            border-radius: 0.4rem;
            margin-bottom: 0.5rem;
        }
        .mantra-box {
            font-size: 1.1rem;
            line-height: 1.8;
            color: #fdfdfd;
            background-color: rgba(255, 255, 255, 0.06);
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            margin-bottom: 0.5rem;
            white-space: pre-wrap;
        }
        .daily-reflection {
            background: #fff8e5;
            padding: 0.75rem 1rem;
            border-radius: 0.6rem;
            border-left: 4px solid #e0b45a;
            margin-bottom: 1rem;
            color: #3a2503;
        }
        .home-section-title {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 0.4rem;
        }
        .stButton > button {
            border-radius: 999px;
            padding: 0.35rem 1.1rem;
            border: none;
        }
        @media (max-width: 768px) {
            .answer-text {
                font-size: 0.98rem;
            }
            .mantra-box {
                font-size: 1.0rem;
            }
            .stButton > button {
                width: 100%;
                margin-bottom: 0.25rem;
            }
            .block-container {
                padding-left: 1rem;
                padding-right: 1rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _escape_html(text: str) -> str:
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_answer_html(text: str):
    """Render a story/answer block with consistent styling."""
    safe = _escape_html(text)
    st.markdown(
        f"<div class='answer-text'>{safe}</div>",
        unsafe_allow_html=True,
    )


def render_source_html(text: str):
    """Render a small source/passage block."""
    safe = _escape_html(text)
    st.markdown(
        f"<div class='source-text'>{safe}</div>",
        unsafe_allow_html=True,
    )


def render_mantra_html(text: str):
    """Render a mantra text block, preserving line breaks."""
    safe = _escape_html(text)
    st.markdown(
        f"<div class='mantra-box'>{safe}</div>",
        unsafe_allow_html=True,
    )