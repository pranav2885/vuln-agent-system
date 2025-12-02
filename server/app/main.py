from dotenv import load_dotenv
load_dotenv()  # Load .env file before importing other modules

from fastapi import FastAPI
from .routes import router as routes_router

app = FastAPI(title="Vuln AI Server (Prototype)")
app.include_router(routes_router)
