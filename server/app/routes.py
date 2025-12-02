from fastapi import APIRouter, UploadFile, File, BackgroundTasks, Header, HTTPException
import uuid, json
from .storage import save_agg, save_ai, get_ai
from .ai_adapter import analyze_agg
import os

router = APIRouter()
API_TOKEN = os.getenv("API_TOKEN", "server-demo-token")

@router.post("/api/upload")
async def upload(file: UploadFile = File(...), authorization: str = Header(None), bg: BackgroundTasks = None):
    # Simple token check
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    token = authorization.split(" ",1)[1]
    if token != API_TOKEN:
        raise HTTPException(401, "Invalid token")

    content = await file.read()
    scan_id = str(uuid.uuid4())
    save_agg(scan_id, content)
    try:
        agg = json.loads(content)
    except Exception:
        agg = {"raw": "could not parse uploaded JSON"}

    # run analysis in background
    if bg:
        bg.add_task(run_analysis, agg, scan_id)
    else:
        run_analysis(agg, scan_id)

    return {"scan_id": scan_id, "status": "queued"}

def run_analysis(agg, scan_id):
    ai_out = analyze_agg(agg)
    save_ai(scan_id, ai_out)

@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    token = authorization.split(" ",1)[1]
    if token != API_TOKEN:
        raise HTTPException(401, "Invalid token")
    ai = get_ai(scan_id)
    if ai is None:
        return {"scan_id": scan_id, "status": "pending"}
    return {"scan_id": scan_id, "status": "done", "ai": ai}
