from typing import Optional

from pydantic import BaseModel, Field


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
    distance: Optional[float]
    altitude: Optional[float]
    precisionBits: Optional[int]
    hopsAway: Optional[int]
    # selectedCategory: Optional[int] = 1

class AllNodesResponse(BaseModel):
    total: int
    start: int
    page: int
    nodes: list[NodeDetailsResponse]

class PositionUpdateRequest(BaseModel):
    latitudeI: int
    longitudeI: int
    altitude: int
    time: int
    locationSource: str
    timestamp: int
    groundSpeed: int
    groundTrack: int
    satsInView: int
    precisionBits: int
    latitude: float
    longitude: float

class NotificationRequest(BaseModel):
    nodeNum: int
    message: str = Field(..., max_length=200)

class PendingNotificationsResponse(BaseModel):
    id: int
    timestamp: int
    toId: int
    message: str
    received: bool = False
    attempts: int = 0
    txId: Optional[int] = None

class PositionResponse(BaseModel):
    latitude: float
    longitude: float

class TracerouteDetail(BaseModel):
    rxTime: int
    fromId: int
    toId: int
    routeTowards: list[int]
    routeBack: list[int]
