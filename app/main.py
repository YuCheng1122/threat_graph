# third party package
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import uvicorn

from app.routes.view import router as view_router
from app.routes.auth import router as auth_router
from app.routes.wazuh import router as wazuh_router
from app.ext.error_handler import add_error_handlers
from fastapi.middleware.cors import CORSMiddleware  
from app.middleware.auth import AuthMiddleware

# Load environment variables
load_dotenv()

# Set up main application logger
logging.basicConfig(level=logging.DEBUG)
app_handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
app_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app_logger = logging.getLogger("app")
app_logger.addHandler(app_handler)

# Set up user activity logger
user_activity_handler = RotatingFileHandler('user_activity.log', maxBytes=10000, backupCount=3)
user_activity_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
user_activity_logger = logging.getLogger("user_activity")
user_activity_logger.addHandler(user_activity_handler)

app = FastAPI(
    title="AIXSOAR ATH API",
    description="API description",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
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

# Health check endpoint
@app.get("/health")
async def health_check():
    app_logger.info("Health check performed")
    return {"status": "healthy"}

# Startup event
@app.on_event("startup")
async def startup_event():
    app_logger.info("Application is starting up")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    app_logger.info("Application is shutting down")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)