from typing import Optional
from pydantic import BaseModel

class Decoded(BaseModel):
    portnum: str
    payload: str # Message content
    bitfield: int
    text: str

class MessageReceived(BaseModel):
    fromId: int
    toId: int
    fromName: Optional[str] = None
    decoded: Decoded
    id: int
    rxSnr: float # Signal to Noise Ratio
    hopLimit: int # Maximum number of hops
    rxRssi: int # Received Signal Strength Indicator
    hopStart: int
    rxTime: Optional[int] = None
    wantAck: Optional[bool] = None
    publicKey: Optional[str] = None
    pkiEncrypted: Optional[bool] = None

    def db_payload(self) -> dict:
        return {
            'fromId': self.fromId,
            'toId': self.toId,
            'fromName': self.fromName,
            'message': self.decoded.text,
            'rxTime': self.rxTime,
            'rxSnr': self.rxSnr,
            'rxRssi': self.rxRssi,
            'hopStart': self.hopStart,
            'hopLimit': self.hopLimit,
        }

class User(BaseModel):
    id: str
    longName: Optional[str] = None
    shortName: Optional[str] = None
    macaddr: Optional[str] = None
    hwModel: Optional[str] = None
    publicKey: Optional[str] = None
    role: Optional[str] = None
    isLicensed: Optional[bool] = None

class Position(BaseModel):
    latitudeI: Optional[int] = None
    longitudeI: Optional[int] = None
    altitude: Optional[int] = None
    time: Optional[int] = None
    locationSource: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class DeviceMetrics(BaseModel):
    batteryLevel: Optional[int] = None
    voltage: Optional[float] = None
    channelUtilization: Optional[float] = None
    airUtilTx: Optional[float] = None
    uptimeSeconds: Optional[int] = None

class NodeBase(BaseModel):
    num: int
    user: User
    position: Optional[Position] = None
    snr: Optional[float] = None
    lastHeard: Optional[int] = None
    deviceMetrics: Optional[DeviceMetrics] = None
    isFavorite: Optional[bool] = None
    hopsAway: Optional[int] = None
