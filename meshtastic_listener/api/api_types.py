from typing import Optional

from pydantic import BaseModel


class NodeDetailsResponse(BaseModel):
    nodeNum: int
    longName: Optional[str]
    shortName: Optional[str]
    macAddr: Optional[str]
    hwModel: Optional[str]
    publicKey: Optional[str]
    nodeRole: Optional[str]
    lastHeard: Optional[int]
    latitude: Optional[float]
    longitude: Optional[float]
    altitude: Optional[float]
    precisionBits: Optional[int]
    hopsAway: Optional[int]
    isHost: Optional[bool]
    hostSoftwareVersion: Optional[str]
    # selectedCategory: Optional[int] = 1

class AllNodesResponse(BaseModel):
    total: int
    start: int
    page: int
    nodes: list[NodeDetailsResponse]

class PositionResponse(BaseModel):
    latitude: float
    longitude: float

class TracerouteDetail(BaseModel):
    rxTime: int
    fromId: int
    toId: int
    routeTowards: list[int]
    routeBack: list[int]
