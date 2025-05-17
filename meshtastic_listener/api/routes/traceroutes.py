from typing import Annotated, Optional
from time import time

from meshtastic_listener.api.db_session import get_db_instance
from meshtastic_listener.api.api_types import TracerouteDetail
from meshtastic_listener.listener_db.listener_db import ListenerDb

from fastapi import APIRouter, Depends

router = APIRouter(
    prefix="/traceroutes",
    tags=["traceroutes"],
    responses={404: {"description": "Not found"}},
)

@router.get('/', )
async def retrieve_traceroute_entries(
    db: Annotated[ListenerDb, Depends(get_db_instance)]
) -> list[TracerouteDetail]:
    return [
        TracerouteDetail(
            rxTime=tr.rxTime,
            fromId=tr.fromId,
            toId=tr.toId,
            routeTowards=tr.tracerouteDetails.get('route', [tr.toId]),
            routeBack=tr.tracerouteDetails.get('routeBack', [tr.fromId])
        ) for tr in db.retrieve_traceroute_results()
    ]
    