from typing import Annotated, Union
from time import time

from meshtastic_listener.api.db_session import get_db_instance
from meshtastic_listener.api.api_types import PositionResponse
from meshtastic_listener.listener_db.listener_db import ListenerDb

from fastapi import APIRouter, Depends

router = APIRouter(
    prefix="/utils",
    tags=["Utilities"],
    responses={404: {"description": "Not found"}},
)


@router.get('/map_center', response_model=PositionResponse)
async def get_position_coordinates(
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> PositionResponse:
    """
    Get the coordinates of the center of the mesh.
    """
    latitude, longitude = db.calculate_center_coordinates()
    return PositionResponse(
        latitude=latitude,
        longitude=longitude
    )