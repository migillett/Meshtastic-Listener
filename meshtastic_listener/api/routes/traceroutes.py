from typing import Annotated, Union
from time import time

from meshtastic_listener.api.db_session import get_db_instance
from meshtastic_listener.listener_db.listener_db import ListenerDb
from meshtastic_listener.data_structures import (
    TransmissionPayload,
    EnvironmentPayload,
    DevicePayload,
)

from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter(
    prefix="/traceroutes",
    tags=["traceroutes"],
    responses={404: {"description": "Not found"}},
)