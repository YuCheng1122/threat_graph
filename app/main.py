# third party package
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import logging
from pathlib import Path


from app.routes.view import router as view_router
from app.routes.auth import router as auth_router
from app.ext.error import GraphControllerError, NotFoundUserError, ElasticsearchError, RequestParamsError
from app.ext.error_handler import graph_controller_error_handler, not_found_user_error_handler, elasticsearch_error_handler, request_params_error_handler

# Load environment variables
load_dotenv()

app = FastAPI()

logging.basicConfig(level=logging.INFO)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include the API router
app.include_router(view_router, prefix="/api")
app.include_router(auth_router, prefix="/api/auth")

# Include error handlers
app.add_exception_handler(GraphControllerError, graph_controller_error_handler)
app.add_exception_handler(NotFoundUserError, not_found_user_error_handler)
app.add_exception_handler(ElasticsearchError, elasticsearch_error_handler)
app.add_exception_handler(RequestParamsError, request_params_error_handler)


# Serve the HTML file at the root URL
@app.get("/", response_class=HTMLResponse)
async def get_html():
    with open(Path("static/index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)













