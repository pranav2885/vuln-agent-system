import os, json
STORAGE_DIR = os.getenv("STORAGE_DIR", "./data")
os.makedirs(STORAGE_DIR, exist_ok=True)

def save_agg(scan_id, content_bytes):
    path = os.path.join(STORAGE_DIR, f"{scan_id}.json")
    with open(path, "wb") as fh:
        fh.write(content_bytes)
    return path

def save_ai(scan_id, ai_obj):
    path = os.path.join(STORAGE_DIR, f"{scan_id}_ai.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(ai_obj, fh, indent=2)
    return path

def get_ai(scan_id):
    path = os.path.join(STORAGE_DIR, f"{scan_id}_ai.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return None
