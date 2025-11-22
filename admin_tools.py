import os
import json
import streamlit as st

from rag import get_collection, embed_query, client
from database import (
    load_practice_candidates,
    save_practice_candidates,
    load_approved_practices,
)


def scan_practice_candidates_from_chroma(kind_filter=None, book_filter=None, extra_keywords=None):
    """
    Scan the Chroma collection for possible mantra / meditation practices.

    kind_filter:
      - "mantra" -> only mantra
      - "meditation" -> only meditation
      - None -> both

    book_filter:
      - optional list of base filenames (["Gita.pdf", ...])

    extra_keywords:
      - optional list of extra phrases to add to search
    """
    col = get_collection()
    if col.count() == 0:
        return []

    existing = load_practice_candidates()
    approved = load_approved_practices()

    if book_filter:
        book_filter = set(book_filter)
    else:
        book_filter = None

    if extra_keywords:
        extra_keywords = [w for w in extra_keywords if w]
    else:
        extra_keywords = []

    approved_texts = set()
    for kind in ("mantra", "meditation"):
        for item in approved.get(kind, []):
            text_val = item.get("text", "")
            if text_val:
                approved_texts.add(text_val)

    seen_keys = set()
    for c in existing:
        key = (c.get("kind"), c.get("source"), c.get("text"))
        seen_keys.add(key)

    queries = {
        "mantra": [
            "mantra", "japa", "chanting", "holy name", "nama", "stotra", "kirtan",
        ],
        "meditation": [
            "meditation", "dhyana", "concentration", "inner silence",
            "awareness of breath", "quiet mind", "watching thoughts",
        ],
    }

    if kind_filter in ("mantra", "meditation"):
        active_queries = {kind_filter: queries[kind_filter][:]}
    else:
        active_queries = {k: v[:] for k, v in queries.items()}

    for k in active_queries:
        active_queries[k].extend(extra_keywords)

    new_candidates = list(existing)

    for kind, words in active_queries.items():
        for word in words:
            try:
                emb = embed_query(word)
                res = col.query(query_embeddings=[emb], n_results=5)
            except Exception:
                continue

            docs_list = res.get("documents") or []
            metas_list = res.get("metadatas") or []
            if not docs_list or not metas_list:
                continue

            docs = docs_list[0] or []
            metas = metas_list[0] or []

            for doc, meta in zip(docs, metas):
                text = (doc or "").strip()
                if not text:
                    continue
                source = (meta or {}).get("source", "")

                if book_filter:
                    src_base = os.path.basename(source) if source else ""
                    if src_base not in book_filter:
                        continue

                key = (kind, source, text)
                if key in seen_keys:
                    continue
                if text in approved_texts:
                    continue

                snippet = text if len(text) <= 800 else text[:800] + " ..."
                new_candidates.append(
                    {
                        "kind": kind,
                        "source": source,
                        "text": snippet,
                        "approved": False,
                    }
                )
                seen_keys.add(key)

    save_practice_candidates(new_candidates)
    return new_candidates


def fetch_online_practices(deity_name: str, scope: str, level_label: str):
    """
    Use the OpenAI API to suggest safe, traditional mantras or meditation
    practices for a given deity, grouped by level.
    """
    deity = (deity_name or "").strip()
    if not deity:
        return []

    scope = scope.lower()
    if scope == "mantras":
        scope_desc = "Only mantras (names, japa, stotras) for this deity."
    elif scope == "meditations":
        scope_desc = "Only meditation approaches, dhyana, visualisations, gentle breath-awareness for this deity."
    else:
        scope_desc = "Both mantras and meditation approaches for this deity."

    level_label = (level_label or "Beginner").strip()

    system_msg = """
You are a careful Hindu spiritual assistant.

You may suggest:
- Well-known, public mantras and holy names,
- Simple, safe meditation approaches (dhyana) that any sincere seeker can practice,
- General dharmic guidance grounded in traditional teachings.

STRICT RULES:
- Do NOT invent new mantras or give secret/initiatory formulas.
- Do NOT include advanced or dangerous techniques (no breath retention, no complex kundalini work, no sexual practices).
- Do NOT give medical, psychological, or legal advice.
- Only give gentle, devotional, and simple things that are safe for the general public.
- If you are not sure about the source of a mantra, clearly mark it as "uncertain, please verify".
- Keep each suggestion short and focused.

You MUST answer in pure JSON. No code fences.
The JSON format is:

{
  "practices": [
    {
      "kind": "mantra" or "meditation",
      "title": "short title for this practice",
      "deity": "name of the deity",
      "level": "beginner" or "intermediate" or "deeper",
      "mantra_text": "exact mantra or holy name lines (for mantras), empty for meditation",
      "instructions": "short explanation of how to use this mantra or meditation, in simple language",
      "source_hint": "short note about traditional source or lineage if known"
    },
    ...
  ]
}
"""

    user_msg = f"""
Deity or god name: {deity}

Scope: {scope_desc}

Level focus: {level_label}

Please suggest 3–5 practices in total that are suitable for this deity and level.
"""

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
        )
        raw = (resp.choices[0].message.content or "").strip()
    except Exception as e:
        st.error(f"Online practice search failed: {e}")
        return []

    if raw.startswith("```"):
        lines = raw.splitlines()
        cleaned_lines = []
        for line in lines:
            if line.strip().startswith("```"):
                continue
            if line.strip().lower() == "json":
                continue
            cleaned_lines.append(line)
        raw = "\n".join(cleaned_lines).strip()

    try:
        data = json.loads(raw)
    except Exception as e:
        st.error(f"Could not parse online suggestions (expected JSON): {e}")
        return []

    practices = data.get("practices", [])
    cleaned = []
    for p in practices:
        if not isinstance(p, dict):
            continue
        kind = (p.get("kind") or "").lower()
        if kind not in ("mantra", "meditation"):
            continue
        cleaned.append(p)
    return cleaned