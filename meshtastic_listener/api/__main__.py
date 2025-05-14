import toml
from os import path
from pathlib import Path

from meshtastic_listener.api.routes import (
    notifications, nodes, telemetry, utils,
    traceroutes
)

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="Meshtastic Listener API",
    version=toml.load('pyproject.toml')['tool']['poetry']['version']
)

templates = Jinja2Templates(directory=path.join(BASE_DIR, "templates"))

app.include_router(nodes.router)
app.include_router(notifications.router)
app.include_router(telemetry.router)
app.include_router(utils.router)
app.include_router(traceroutes.router)

app.mount("/static", StaticFiles(directory=path.join(BASE_DIR, "static")), name="static")


@app.get("/", tags=["Root"])
async def render_home_page(request: Request) -> HTMLResponse:
    """
    Render the home page.
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


if __name__ == "__main__":
    uvicorn.run(app)
