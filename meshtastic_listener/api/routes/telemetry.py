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
    prefix="/telemetry",
    tags=["Telemetry"],
    responses={404: {"description": "Not found"}},
)


@router.patch('/{node_num}', status_code=status.HTTP_202_ACCEPTED)
async def update_node_telemetry(
    node_num: int,
    telemetry: Union[TransmissionPayload, EnvironmentPayload, DevicePayload],
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> None:
    """
    Update the telemetry of a node in the DB.
    """
    rxTime = int(time())

    if isinstance(telemetry, TransmissionPayload):
        db.insert_transmission_metrics(
            node_num=node_num, rxTime=rxTime, telemetry=telemetry)
        
    elif isinstance(telemetry, EnvironmentPayload):
        db.insert_environment_metrics(
            node_num=node_num, rxTime=rxTime, telemetry=telemetry)
        
    elif isinstance(telemetry, DevicePayload):
        db.insert_device_metrics(
            node_num=node_num, rxTime=rxTime, telemetry=telemetry)
        
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid telemetry type"
        )
