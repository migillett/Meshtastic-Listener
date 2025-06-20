from typing import Optional
from enum import StrEnum
from datetime import datetime

from pydantic import BaseModel, Field


class InsufficientDataError(Exception):
    pass

class NodeRoles(StrEnum):
    CLIENT = "CLIENT"
    CLIENT_MUTE = "CLIENT_MUTE"
    CLIENT_HIDDEN = "CLIENT_HIDDEN"
    TRACKER = "TRACKER"
    LOST_AND_FOUND = "LOST_AND_FOUND"
    SENSOR = "SENSOR"
    TAK = "TAK"
    TAK_TRACKER = "TAK_TRACKER"
    REPEATER = "REPEATER"
    ROUTER = "ROUTER"
    ROUTER_LATE = "ROUTER_LATE"
    ROUTER_CLIENT = "ROUTER_CLIENT" # RIP router client

class Decoded(BaseModel):
    portnum: str
    bitfield: Optional[int] = None
    text: Optional[str] = ''

class MessageReceived(BaseModel):
    fromId: int
    toId: int
    decoded: Decoded
    id: int
    rxSnr: float = 0.0 # Signal to Noise Ratio. The higher the better
    rxRssi: int = 0 # Received Signal Strength Indicator. The higher the better
    hopLimit: Optional[int] = None # Maximum number of hops
    hopStart: Optional[int] = None
    wantAck: Optional[bool] = None
    publicKey: Optional[str] = None
    pkiEncrypted: Optional[bool] = None
    rxTime: int = Field(default=int(datetime.now().timestamp()))

    def __init__(self, **data):
        data['fromId'] = data.pop('from')
        data['toId'] = data.pop('to')
        super().__init__(**data)

class User(BaseModel):
    id: str
    longName: Optional[str] = None
    shortName: Optional[str] = None
    macaddr: Optional[str] = None
    hwModel: Optional[str] = None
    publicKey: Optional[str] = None
    role: Optional[NodeRoles] = None

class Position(BaseModel):
    latitudeI: Optional[int] = None
    longitudeI: Optional[int] = None
    altitude: Optional[int] = None
    time: Optional[int] = None
    locationSource: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class DevicePayload(BaseModel):
    batteryLevel: Optional[int] = None
    voltage: Optional[float] = None
    channelUtilization: Optional[float] = None
    uptimeSeconds: Optional[int] = None

class TransmissionPayload(BaseModel):
    airUtilTx: Optional[float] = None
    numPacketsTx: Optional[int] = None
    numPacketsRx: Optional[int] = None
    numPacketsRxBad: Optional[int] = None
    numOnlineNodes: Optional[int] = None
    numTotalNodes: Optional[int] = None
    numRxDupe: Optional[int] = None
    numTxRelay: Optional[int] = None
    numTxRelayCanceled: Optional[int] = None

class WaypointPayload(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    icon: int
    latitudeI: int
    longitudeI: int
    expire: int
    lockedTo: Optional[int] = None

class EnvironmentPayload(BaseModel):
    temperature: Optional[float] = None
    relativeHumidity: Optional[float] = None
    barometricPressure: Optional[float] = None
    gasResistance: Optional[float] = None
    iaq: Optional[int] = None

class NodeBase(BaseModel):
    num: int
    user: User
    snr: Optional[float] = None
    lastHeard: Optional[int] = None
    isFavorite: bool = False
    hopsAway: Optional[int] = None
    position: Position = Field(default=Position())
    deviceMetrics: DevicePayload = Field(default=DevicePayload())
    isFavorite: bool = False
    isHost: bool = False
    hostSoftwareVersion: Optional[str] = None

class TracerouteStatistics(BaseModel):
    total: int = 0
    successes: int = 0
    avgTraceDuration: float = 0

    def average(self) -> float:
        if self.total == 0:
            raise InsufficientDataError('No traceroute data available to calculate average success rate.')
        return round((self.successes / self.total) * 100, 2)

class NodeHealthCheck(BaseModel):
    nodeNum: int
    startTs: int = 0
    endTs: int = Field(default=int(datetime.now().timestamp()))
    channelUsage: float = Field(ge=0.0, le=100.0) # percentage
    TracerouteStatistics: TracerouteStatistics
    environmentMetrics: EnvironmentPayload = Field(default=EnvironmentPayload())

    def status(self) -> str:
        status = f'''{datetime.fromtimestamp(self.startTs).strftime('%Y-%m-%d %H:%M')}
CH USAGE: {round(self.channelUsage, 2)}%
TR SUCCESS: {self.TracerouteStatistics.average()}%
TR AVG DUR: {int(self.TracerouteStatistics.avgTraceDuration)}s'''

        if self.environmentMetrics.temperature is not None:
            status += f'\nTEMP: {round(self.environmentMetrics.temperature, 2)}°C'
        if self.environmentMetrics.relativeHumidity is not None:
            status += f'\nHUMIDITY: {round(self.environmentMetrics.relativeHumidity, 2)}%'
        return status.strip()
