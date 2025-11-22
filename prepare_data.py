import os
import glob
import json
from typing import List

import pypdf
import chromadb
from openai import OpenAI
from ebooklib import epub, ITEM_DOCUMENT
from bs4 import BeautifulSoup
from pdf2image import convert_from_path
import pytesseract

# ----------------- CONFIG -----------------

client = OpenAI()

BOOKS_DIR = "books"
COLLECTION_NAME = "saint_books"
UNREADABLE_FILE = "unreadable_books.json"

CHROMA_PATH = "./chroma_db"

# Approximate chunk size in characters per chunk
CHUNK_SIZE_CHARS = 1500
CHUNK_OVERLAP_CHARS = 200

# Embedding batch size: how many chunks per API call
EMBED_BATCH_SIZE = 50


# ----------------- UNREADABLE TRACKING -----------------

def load_unreadable() -> dict:
    if not os.path.exists(UNREADABLE_FILE):
        return {}
    try:
        with open(UNREADABLE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_unreadable(data: dict) -> None:
    with open(UNREADABLE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ----------------- TEXT EXTRACTION -----------------

def ocr_pdf(path: str, max_pages: int = 10) -> str:
    """
    OCR fallback for scanned PDFs.
    To control cost/time, we only OCR the first `max_pages` pages.
    """
    try:
        pages = convert_from_path(path, dpi=200)
    except Exception as e:
        print(f"   ⚠ OCR failed for {path}: {e}")
        return ""

    texts: List[str] = []
    for i, page in enumerate(pages):
        if i >= max_pages:
            break
        try:
            text = pytesseract.image_to_string(page)
            if text.strip():
                texts.append(text)
        except Exception as e:
            print(f"   ⚠ OCR page {i} failed: {e}")
            continue

    return "\n".join(texts)


def extract_text_from_pdf(path: str) -> str:
    """
    Extract text from a PDF. If no selectable text is found,
    fall back to OCR.
    """
    try:
        reader = pypdf.PdfReader(path)
    except Exception as e:
        print(f"   ❌ Failed to read PDF {path}: {e}")
        return ""

    text_parts: List[str] = []

    for idx, page in enumerate(reader.pages):
        try:
            t = page.extract_text()
            if t:
                text_parts.append(t)
        except Exception as e:
            print(f"   ⚠ Error extracting page {idx} of {path}: {e}")
            continue

    text = "\n".join(text_parts)

    if not text.strip():
        print("   ⚠ No selectable text in PDF, trying OCR fallback...")
        text = ocr_pdf(path)

    return text


def extract_text_from_epub(path: str) -> str:
    """
    Extract text from EPUB using ebooklib + BeautifulSoup.
    """
    try:
        book = epub.read_epub(path)
    except Exception as e:
        print(f"   ❌ Failed to read EPUB {path}: {e}")
        return ""

    texts: List[str] = []

    for item in book.get_items_of_type(ITEM_DOCUMENT):
        try:
            html = item.get_content()
            soup = BeautifulSoup(html, "lxml")

            # Remove scripts/styles
            for s in soup(["script", "style"]):
                s.extract()

            t = soup.get_text(separator="\n")
            t = t.strip()
            if t:
                texts.append(t)
        except Exception as e:
            print(f"   ⚠ Error extracting from EPUB item: {e}")
            continue

    return "\n\n".join(texts)


def extract_text(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        return extract_text_from_pdf(path)
    elif ext == ".epub":
        return extract_text_from_epub(path)
    else:
        print(f"   ⚠ Unsupported file type for {path}")
        return ""


# ----------------- CHUNKING -----------------

def chunk_text(text: str, chunk_size: int = CHUNK_SIZE_CHARS, overlap: int = CHUNK_OVERLAP_CHARS) -> List[str]:
    """
    Very simple character-based chunking with small overlap.
    Keeps chunks small enough so that embedding batches stay well under token limits.
    """
    text = text.strip()
    if not text:
        return []

    chunks: List[str] = []
    start = 0
    length = len(text)

    while start < length:
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk.strip())
        start = end - overlap  # slight overlap
        if start < 0:
            start = 0

    # Remove empty
    chunks = [c for c in chunks if c.strip()]
    return chunks


# ----------------- EMBEDDINGS (BATCHED) -----------------

def embed_texts(chunks: List[str]) -> List[List[float]]:
    """
    Embeds text chunks in safe batches to avoid exceeding token limits.
    """
    embeddings: List[List[float]] = []

    if not chunks:
        return embeddings

    print(f"   🔣 Creating embeddings in batches of {EMBED_BATCH_SIZE}...")

    for i in range(0, len(chunks), EMBED_BATCH_SIZE):
        batch = chunks[i: i + EMBED_BATCH_SIZE]

        try:
            resp = client.embeddings.create(
                model="text-embedding-3-small",
                input=batch,
            )
        except Exception as e:
            print(f"   ❌ Embedding batch failed: {e}")
            raise

        for e in resp.data:
            embeddings.append(e.embedding)

    return embeddings


# ----------------- INDEXING -----------------

def index_single_book(path: str, collection, unreadable: dict) -> None:
    abs_path = os.path.abspath(path)
    file_name = os.path.basename(path)

    print(f"📘 Processing: {path}")

    text = extract_text(path)
    if not text or not text.strip():
        print("   ❌ No text extracted, marking unreadable.")
        unreadable[abs_path] = "no_text_extracted"
        return

    chunks = chunk_text(text)
    if not chunks:
        print("   ❌ Could not create chunks, marking unreadable.")
        unreadable[abs_path] = "chunking_failed"
        return

    # If it was previously unreadable and now succeeded, clear it
    if abs_path in unreadable:
        del unreadable[abs_path]

    print("   🗑 Removing old chunks from collection...")
    collection.delete(where={"source": abs_path})

    print(f"   🔣 Embedding {len(chunks)} chunks...")
    embeddings = embed_texts(chunks)

    print("   📦 Storing in Chroma...")
    ids = [f"{file_name}_chunk_{i}" for i in range(len(chunks))]
    metadatas = [{"source": abs_path} for _ in chunks]

    collection.add(
        ids=ids,
        documents=chunks,
        embeddings=embeddings,
        metadatas=metadatas,
    )

    print(f"   ✅ Stored {len(chunks)} chunks for {file_name}.\n")


def main() -> None:
    print("\n🔍 Starting full indexing of books...\n")

    os.makedirs(BOOKS_DIR, exist_ok=True)

    unreadable = load_unreadable()

    # Set up Chroma
    chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = chroma_client.get_or_create_collection(COLLECTION_NAME)

    # All PDF/EPUB in books/
    paths = glob.glob(os.path.join(BOOKS_DIR, "*.pdf")) + glob.glob(
        os.path.join(BOOKS_DIR, "*.epub")
    )

    if not paths:
        print("⚠ No PDF/EPUB files found in 'books/' folder.")
        return

    for path in sorted(paths):
        index_single_book(path, collection, unreadable)

    save_unreadable(unreadable)

    print("📄 Unreadable books snapshot:")
    print(json.dumps(unreadable, indent=2, ensure_ascii=False))
    print("\n✅ Full indexing complete.\n")


if __name__ == "__main__":
    main()