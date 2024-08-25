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

# Load environment variables
load_dotenv()

# Set up centralized application logger
def setup_logger(name, log_file, level=logging.INFO):
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    handler.setFormatter(formatter)
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    
    return logger

# Create centralized logger
app_logger = setup_logger('app_logger', 'app.log', level=logging.DEBUG)

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
    
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)