from fastapi import FastAPI
from src.api import app as original_app

app = FastAPI()

app.mount("/api", original_app)