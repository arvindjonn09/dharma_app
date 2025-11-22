import os
import time
import json
import glob
import pypdf
import chromadb
from openai import OpenAI
from ebooklib import epub, ITEM_DOCUMENT
from bs4 import BeautifulSoup
from pdf2image import convert_from_path
import pytesseract

client = OpenAI()

BOOKS_DIR = "books"
COLLECTION_NAME = "saint_books"
INDEX_STATE_FILE = "index_state.json"
UNREADABLE_FILE = "unreadable_books.json"
SLEEP_SECONDS = 300  # 5 minutes


# ----- helpers (copies of prepare_data logic, simplified) -----

def load_state():
    if not os.path.exists(INDEX_STATE_FILE):
        return {}
    try:
        return json.load(open(INDEX_STATE_FILE, "r"))
    except json.JSONDecodeError:
        return {}


def save_state(state):
    json.dump(state, open(INDEX_STATE_FILE, "w"), indent=2)


def load_unreadable():
    if not os.path.exists(UNREADABLE_FILE):
        return {}
    try:
        return json.load(open(UNREADABLE_FILE, "r"))
    except json.JSONDecodeError:
        return {}


def save_unreadable(data):
    json.dump(data, open(UNREADABLE_FILE, "w"), indent=2)


def ocr_pdf(path: str, max_pages: int = 10) -> str:
    try:
        pages = convert_from_path(path, dpi=200)
    except Exception:
        return ""
    texts = []
    for i, page in enumerate(pages):
        if i >= max_pages:
            break
        try:
            t = pytesseract.image_to_string(page)
            if t.strip():
                texts.append(t)
        except Exception:
            continue
    return "\n".join(texts)


def extract_text_from_pdf(path: str) -> str:
    try:
        reader = pypdf.PdfReader(path)
    except Exception:
        return ""
    text = ""
    for page in reader.pages:
        try:
            t = page.extract_text()
            if t:
                text += t + "\n"
        except Exception:
            continue
    if not text.strip():
        text = ocr_pdf(path)
    return text


def extract_text_from_epub(path: str) -> str:
    try:
        book = epub.read_epub(path)
    except Exception:
        return ""
    texts = []
    for item in book.get_items_of_type(ITEM_DOCUMENT):
        try:
            html = item.get_content()
            soup = BeautifulSoup(html, "lxml")
            for s in soup(["script", "style"]):
                s.extract()
            t = soup.get_text(separator="\n").strip()
            if t:
                texts.append(t)
        except Exception:
            continue
    return "\n\n".join(texts)


def extract_text(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        return extract_text_from_pdf(path)
    elif ext == ".epub":
        return extract_text_from_epub(path)
    return ""


def chunk_text(text: str, max_chars: int = 800):
    paragraphs = text.split("\n\n")
    chunks = []
    current = ""
    for p in paragraphs:
        p = p.strip()
        if not p:
            continue
        if len(current) + len(p) <= max_chars:
            current += p + "\n\n"
        else:
            chunks.append(current.strip())
            current = p + "\n\n"
    if current.strip():
        chunks.append(current.strip())
    return chunks


def embed_texts(chunks):
    """
    Embeds text chunks in safe batches to avoid exceeding token limits.
    """
    embeddings = []
    BATCH_SIZE = 50  # safe number of chunks per API call

    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i : i + BATCH_SIZE]

        resp = client.embeddings.create(
            model="text-embedding-3-small",
            input=batch,
        )

        for e in resp.data:
            embeddings.append(e.embedding)

    return embeddings


def get_collection():
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    return chroma_client.get_or_create_collection(name=COLLECTION_NAME)


# ----- core indexing for a single file -----

def index_book(path: str, collection, unreadable: dict):
    abs_path = os.path.abspath(path)
    print(f"📘 Indexing: {path}")

    text = extract_text(path)
    if not text.strip():
        print("   ❌ No text extracted, marking unreadable.")
        unreadable[abs_path] = "no_text_extracted"
        return

    chunks = chunk_text(text)
    if not chunks:
        print("   ❌ Cannot chunk text, marking unreadable.")
        unreadable[abs_path] = "chunking_failed"
        return

    if abs_path in unreadable:
        del unreadable[abs_path]

    print("   🗑 Deleting old chunks...")
    collection.delete(where={"source": abs_path})

    print("   🔣 Creating embeddings...")
    embeddings = embed_texts(chunks)

    ids = [f"{os.path.basename(path)}_chunk_{i}" for i in range(len(chunks))]
    metas = [{"source": abs_path} for _ in chunks]

    print("   📦 Storing in Chroma...")
    collection.add(ids=ids, documents=chunks, embeddings=embeddings, metadatas=metas)

    print(f"   ✅ Stored {len(chunks)} chunks.\n")


def scan_and_update():
    state = load_state()
    unreadable = load_unreadable()
    collection = get_collection()

    paths = glob.glob(os.path.join(BOOKS_DIR, "*.pdf")) + glob.glob(
        os.path.join(BOOKS_DIR, "*.epub")
    )

    changed = []

    for path in paths:
        try:
            mtime = os.path.getmtime(path)
        except FileNotFoundError:
            continue
        abs_path = os.path.abspath(path)
        last = state.get(abs_path)
        if last is None or mtime > last:
            index_book(path, collection, unreadable)
            state[abs_path] = mtime
            changed.append(path)

    save_state(state)
    save_unreadable(unreadable)
    return changed, unreadable


def main():
    print("📚 Auto indexer started.")
    print(f"Watching: {os.path.abspath(BOOKS_DIR)}")
    print(f"Every {SLEEP_SECONDS} seconds.\n")

    os.makedirs(BOOKS_DIR, exist_ok=True)

    while True:
        print("🔄 Scan cycle...")
        changed, unreadable = scan_and_update()
        if changed:
            print("Updated files:")
            for p in changed:
                print("  -", p)
        else:
            print("No file changes.")

        if unreadable:
            print("Unreadable files:")
            for p, reason in unreadable.items():
                print(f"  - {p} ({reason})")
        print()
        time.sleep(SLEEP_SECONDS)


if __name__ == "__main__":
    main()