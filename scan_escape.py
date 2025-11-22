import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))

# Pattern to catch things like &lt;div ... &gt; and other escaped tags
PATTERN = re.compile(r"&lt;[^>]+&gt;")

def scan_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    matches = list(PATTERN.finditer(text))
    if not matches:
        return
    rel = os.path.relpath(path, ROOT)
    print(f"\n>>> In {rel}:")
    for m in matches:
        snippet = m.group(0)
        # shorten long ones
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        print("   ", snippet)


def main():
    for dirpath, _, files in os.walk(ROOT):
        for name in files:
            if not name.endswith(".py"):
                continue
            full = os.path.join(dirpath, name)
            scan_file(full)


if __name__ == "__main__":
    main()