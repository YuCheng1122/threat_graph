# third party package
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import logging
from pathlib import Path

from app.routes.view import router as view_router
from app.routes.auth import router as auth_router
from app.routes.wazuh import router as wazuh_router  # Changed from auth_router to wazuh_router
from app.ext.error_handler import add_error_handlers
from fastapi.middleware.cors import CORSMiddleware  
from app.middleware.auth import AuthMiddleware

# Load environment variables
load_dotenv()

app = FastAPI(
    title="AIXSOAR ATH API",
    description="API description",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

logging.basicConfig(level=logging.INFO)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update this with the specific origin if necessary
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add authentication middleware
app.add_middleware(AuthMiddleware)

# Include the API router
app.include_router(view_router, prefix="/api/view")
app.include_router(auth_router, prefix="/api/auth")
app.include_router(wazuh_router, prefix="/api/wazuh") 

# Include error handlers
add_error_handlers(app)

# Serve the HTML file at the root URL
@app.get("/", response_class=HTMLResponse)
async def get_html():
    with open(Path("static/index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)