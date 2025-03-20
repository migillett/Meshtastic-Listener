from typing import Optional
from os import environ

from meshtastic_listener.db_utils import ListenerDb

from fastapi import FastAPI, status, Response, HTTPException
import uvicorn
import toml


app = FastAPI(
    title="Mesthastic Listener API",
    description="API for Mesthastic Listener, a tool for managing and interacting with Mesthastic devices.",
    version=toml.load("pyproject.toml")["tool"]["poetry"]["version"]
)

db = ListenerDb(
    hostname=environ.get("POSTGRES_HOSTNAME", "listener_db"),
    username=environ.get("POSTGRES_USER", 'postgres'),
    password=environ.get("POSTGRES_PASSWORD"),
    db_name=environ.get("POSTGRES_DATABASE", 'listener_db')
)

@app.get("/")
async def root():
    return {"message": "Welcome to the Mesthastic Listener API!"}


@app.post('/post', tags=['Messages'], status_code=status.HTTP_202_ACCEPTED)
async def post_message(message: str, destination: Optional[str] = None) -> Response:
    """
    Endpoint to post a message to the Mesthastic Listener.
    
    Args:
        message (str): The message to be sent.
        destination (Optional[str]): The destination node for the message, if any.
    
    Returns:
        Response: HTTP response indicating the status of the operation.
    """
    if not message:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message cannot be empty.")
    
    # Here you would typically send the message to the Mesthastic device
    # For now, we just return a success response
    return Response(content=f"Message '{message}' sent successfully!", status_code=status.HTTP_202_ACCEPTED)

if __name__ == "__main__":
    # Run the API server with uvicorn
    uvicorn.run(app, host="127.0.0.1", port=80, log_level="info")
