import os
import json
import datetime
import chromadb
import streamlit as st
from openai import OpenAI

from database import list_book_names

CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "saint_books"


# ---------- OPENAI CLIENT ----------

def _get_api_key():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key and hasattr(st, "secrets") and "OPENAI_API_KEY" in st.secrets:
        api_key = st.secrets["OPENAI_API_KEY"]
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured.")
    return api_key


client = OpenAI(api_key=_get_api_key())


# ---------- CHROMA COLLECTION ----------

@st.cache_resource
def get_collection():
    try:
        chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
        return chroma_client.get_or_create_collection(COLLECTION_NAME)
    except Exception as e:
        st.error(f"Failed to open Chroma collection: {e}")
        st.stop()


def embed_query(q: str):
    try:
        r = client.embeddings.create(
            model="text-embedding-3-small",
            input=[q],
        )
        return r.data[0].embedding
    except Exception as e:
        st.error(f"Embedding failed: {e}")
        st.stop()


def retrieve_passages(question: str, k: int = 5):
    """
    Search across ALL indexed books.
    Try to include passages from multiple different books if available.
    Returns (docs, metas).
    """
    col = get_collection()
    if col.count() == 0:
        return [], []

    emb = embed_query(question)

    try:
        res = col.query(
            query_embeddings=[emb],
            n_results=10,
        )
    except Exception as e:
        st.error(f"Chroma query failed: {e}")
        return [], []

    if (
        not res
        or "documents" not in res
        or not res["documents"]
        or not res["documents"][0]
    ):
        return [], []

    docs_all = res["documents"][0]
    metas_all = res["metadatas"][0]

    final_docs = []
    final_metas = []
    seen_books = set()

    # First pass: at most 1 chunk per distinct book
    for d, m in zip(docs_all, metas_all):
        src = m.get("source", "")
        book_name = os.path.basename(src) if src else "unknown"

        if book_name in seen_books:
            continue

        final_docs.append(d)
        final_metas.append(m)
        seen_books.add(book_name)

        if len(final_docs) >= k:
            break

    # If still fewer than k, fill up ignoring uniqueness
    if len(final_docs) < k:
        for d, m in zip(docs_all, metas_all):
            if len(final_docs) >= k:
                break
            if d in final_docs:
                continue
            final_docs.append(d)
            final_metas.append(m)

    return final_docs, final_metas


# ---------- STORY ANSWER GENERATION ----------

def answer_question(
    question: str,
    passages: list,
    book_list: list,
    history_messages: list,
    answer_length: str = "Medium",
):
    """Generate a warm, human-style answer based ONLY on the uploaded books."""
    if not passages:
        if book_list:
            joined = ", ".join(book_list)
            return (
                "The uploaded texts do not clearly answer this question.\n\n"
                "Try asking more specifically, for example:\n"
                f"- 'Tell me a story about Krishna from these books: {joined}'\n"
                f"- 'Give me a story about devotion from these books.'\n"
                f"- 'Tell a story about a cow from these books.'"
            )
        else:
            return (
                "No books are indexed yet. Please add some PDF/EPUB files "
                "to the 'books' folder and run indexing."
            )

    # Build context
    context = ""
    for i, p in enumerate(passages):
        context += f"[Passage {i+1}]\n{p}\n\n"

    # Short conversation history
    convo_text_lines = []
    for msg in history_messages[-6:]:
        role = "User" if msg["role"] == "user" else "Assistant"
        convo_text_lines.append(f"{role}: {msg['content']}")
    convo_text = "\n".join(convo_text_lines)

    all_books_str = ", ".join(book_list) if book_list else "Unknown"

    if answer_length.lower() == "short":
        length_hint = "Keep the answer compact: 3–7 sentences total. Focus on the core idea and one small practice."
    elif answer_length.lower() == "detailed":
        length_hint = "You may be more detailed and slow, but still stay focused and not repetitive."
    else:
        length_hint = "Keep the answer balanced in length: not too short, not too long."

    system_prompt = f"""
You are a Hindu STORYTELLER and GENTLE GUIDE for a family-friendly app.

Your knowledge for this conversation comes ONLY from the passages I will give you.

STYLE RULES:
- Do NOT copy long sentences directly from the passages. Paraphrase.
- Be clear, kind, devotional, and conversational.
- Stay within the meaning of the passages and dharmic spirit.
- If the passages are insufficient, say so gently.

ANSWER SHAPE:
1) Directly answer the user's question in 2–4 sentences.
2) Add a short story-like explanation using the passages.
3) Offer 2–4 gentle, practical suggestions for daily life.
4) If a specific deity is central (Shiva, Krishna, Devi, etc.), include
   simple, safe inner ways to connect (remembering qualities, silent name, etc.).
5) End with 1–2 lines highlighting a key dharmic value (if supported by the text).

ANSWER LENGTH HINT:
{length_hint}
"""

    user_prompt = f"""
CONVERSATION SO FAR:
{convo_text}

AVAILABLE BOOKS (for context, not for quoting directly):
{all_books_str}

USER QUESTION NOW:
{question}

PASSAGES FROM THE UPLOADED BOOKS:
{context}

Using ONLY these passages, answer in your own words following the style rules above.
"""

    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return r.choices[0].message.content
    except Exception as e:
        st.error(f"Chat completion failed: {e}")
        return "Sorry, I could not generate a story due to an internal error."


# ---------- IMAGE GENERATION ----------

def classify_story_style(question: str, answer: str) -> str:
    q = (question or "").lower()
    a = (answer or "").lower()

    ack_keywords = [
        "rama", "ramayan", "ramayana", "sita", "ravana", "lakshmana",
        "mahabharata", "arjuna", "karna", "bhishma", "draupadi",
        "kurukshetra", "war", "battle", "fight",
        "shiva", "mahadeva", "rudra", "linga",
        "vishnu", "narayana", "varaha", "narasimha", "vamana",
        "krishna and arjuna", "gita", "devotee vs demon",
        "dharma", "adharma", "truth", "righteousness",
        "sage", "saint", "yogi", "guru",
        "avatar", "goddess", "durga", "kali",
    ]

    clay_keywords = [
        "baby", "child", "kids", "cute", "soft",
        "bal", "little",
        "cow", "calf", "gomata", "gai",
        "krishna", "gopal", "kanha", "butter",
        "ganesha", "ganesh", "modak",
        "hanuman childhood", "bal hanuman",
        "friendship", "kindness", "love",
        "animals", "monkey", "elephant",
        "play", "garden", "forest", "vrindavan",
    ]

    for w in ack_keywords:
        if w in q or w in a:
            return "ack"

    for w in clay_keywords:
        if w in q or w in a:
            return "clay"

    return "ack"


def generate_styled_image(question: str, answer: str):
    style = classify_story_style(question, answer)

    if style == "ack":
        prompt = f"""
Create a vibrant Indian illustrated scene in the style of classic
Amar Chitra Katha (ACK) comics.

Characteristics:
- Bold ink outlines
- Indian facial features
- Traditional clothing, architecture, and ornaments
- Warm colours and detailed backgrounds
- Epic, mythological, or dharmic tone
- NO modern items, NO anime/chibi look

Story context:
Question: {question}
Answer: {answer[:1200]}
"""
    else:
        prompt = f"""
Create a soft 3D claymation-style cartoon illustration.

Characteristics:
- Cute rounded clay characters
- Bright kid-friendly colours
- Soft lighting and smooth textures
- Gentle, devotional feeling
- Perfect for children and animal stories
- NO scary expressions, NO sharp edges

Story context:
Question: {question}
Answer: {answer[:1200]}
"""

    try:
        result = client.images.generate(
            model="dall-e-3",
            prompt=prompt,
            size="1024x1024",
            n=1,
        )
        return result.data[0].url, style
    except Exception as e:
        st.info(f"Image could not be generated: {e}")
        return None, None