import requests, os
from dotenv import load_dotenv

load_dotenv()

BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000")
API_TOKEN = os.getenv("API_TOKEN", "server-demo-token")

def upload_aggregated(path):
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    url = BACKEND.rstrip("/") + "/api/upload"
    with open(path, "rb") as f:
        files = {"file": ("agg.json", f, "application/json")}
        try:
            r = requests.post(url, files=files, headers=headers, timeout=180)
        except Exception as e:
            return {"error": "request_failed", "detail": str(e)}
    try:
        return r.json()
    except Exception:
        return {"status_code": r.status_code, "text": r.text}
