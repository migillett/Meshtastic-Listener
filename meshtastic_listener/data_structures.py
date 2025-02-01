from typing import Optional
from pydantic import BaseModel

class Decoded(BaseModel):
    portnum: str
    payload: str # Message content
    bitfield: Optional[int] = None
    text: str

class MessageReceived(BaseModel):
    fromId: int
    toId: int
    fromName: Optional[str] = None
    decoded: Decoded
    id: int
    rxSnr: float = 0.0 # Signal to Noise Ratio. The higher the better
    rxRssi: int = 0 # Received Signal Strength Indicator. The higher the better
    hopLimit: Optional[int] = None # Maximum number of hops
    hopStart: Optional[int] = None
    rxTime: Optional[int] = None
    wantAck: Optional[bool] = None
    publicKey: Optional[str] = None
    pkiEncrypted: Optional[bool] = None

    def db_payload(self) -> dict:
        return {
            'from': self.fromId,
            'to': self.toId,
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

class EnvironmentPayload(BaseModel):
    temperature: Optional[float] = None
    relativeHumidity: Optional[float] = None
    barometricPressure: Optional[float] = None
    gasResistance: Optional[float] = None
    iaq: Optional[int] = None

class NodeBase(BaseModel):
    num: int
    user: User
    position: Optional[Position] = None
    snr: Optional[float] = None
    lastHeard: Optional[int] = None
    deviceMetrics: Optional[DevicePayload] = None
    isFavorite: Optional[bool] = None
    hopsAway: Optional[int] = None
