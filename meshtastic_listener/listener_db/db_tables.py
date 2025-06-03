from time import time

from sqlalchemy import Column, Integer, String, Float, Boolean, BigInteger, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class AdminNodes(Base):
    '''
    A table to store the admin nodes for the server.
    '''
    __tablename__ = 'admin_nodes'

    nodeNum = Column(BigInteger, primary_key=True, nullable=False)
    description = Column(String(length=200), default=None)
    enabled = Column(Boolean, default=True)
    timestamp = Column(BigInteger, default=int(time()))


class Node(Base):
    __tablename__ = 'nodes'

    nodeNum = Column(BigInteger, primary_key=True)
    longName = Column(String(length=100), default=None)
    shortName = Column(String(length=4), default=None)
    macAddr = Column(String(length=100), default=None)
    hwModel = Column(String(length=100), default=None)
    publicKey = Column(String(length=100), default=None)
    nodeRole = Column(String(length=100), default=None)
    lastHeard = Column(BigInteger, default=None)
    latitude = Column(Float, default=None)
    longitude = Column(Float, default=None)
    altitude = Column(Float, default=None)
    precisionBits = Column(Integer, default=None)
    hopsAway = Column(Integer, default=None)
    isFavorite = Column(Boolean, default=False)
    # tells us if 1. the node here is self or 2. if the node is also running this software (TODO)
    isHost = Column(Boolean, default=False)
    hostSoftwareVersion = Column(String(length=15), default=None)

    @staticmethod
    def cascade_delete(session, node_num: int) -> None:
        """
        Deletes a node and cascades the deletion to all related tables.
        """
        session.query(DeviceMetrics).filter(DeviceMetrics.nodeNum == node_num).delete()
        session.query(TransmissionMetrics).filter(TransmissionMetrics.nodeNum == node_num).delete()
        session.query(EnvironmentMetrics).filter(EnvironmentMetrics.nodeNum == node_num).delete()
        session.query(Subscriptions).filter(Subscriptions.nodeNum == node_num).delete()
        session.query(Neighbor).filter(Neighbor.sourceNodeId == node_num).delete()
        session.query(Neighbor).filter(Neighbor.neighborNodeId == node_num).delete()
        session.query(MessageHistory).filter(MessageHistory.fromId == node_num).delete()
        session.query(MessageHistory).filter(MessageHistory.toId == node_num).delete()
        session.query(OutgoingNotifications).filter(OutgoingNotifications.toId == node_num).delete()
        session.query(Node).filter(Node.nodeNum == node_num).delete()
        session.commit()


class DeviceMetrics(Base):
    __tablename__ = 'device_metrics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(BigInteger, nullable=False)
    nodeNum = Column(BigInteger, nullable=False)
    batteryLevel = Column(Integer, default=None)
    voltage = Column(Float, default=None)
    channelUtilization = Column(Float, default=None)
    uptimeSeconds = Column(BigInteger, default=None)

    
class TransmissionMetrics(Base):
    __tablename__ = 'transmission_metrics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(BigInteger, nullable=False)
    nodeNum = Column(BigInteger, nullable=False)
    airUtilTx = Column(Float, default=None)
    numPacketsTx = Column(Integer, default=None)
    numPacketsRx = Column(Integer, default=None)
    numPacketsRxBad = Column(Integer, default=None)
    numOnlineNodes = Column(Integer, default=None)
    numTotalNodes = Column(Integer, default=None)
    numRxDupe = Column(Integer, default=None)
    numTxRelay = Column(Integer, default=None)
    numTxRelayCanceled = Column(Integer, default=None)


class EnvironmentMetrics(Base):
    __tablename__ = 'environment_metrics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(BigInteger, nullable=False)
    nodeNum = Column(BigInteger, nullable=False)
    temperature = Column(Float, default=None)
    relativeHumidity = Column(Float, default=None)
    barometricPressure = Column(Float, default=None)
    gasResistance = Column(Float, default=None)
    iaq = Column(Integer, default=None)


class Traceroute(Base):
    __tablename__ = 'traceroutes'
    id = Column(BigInteger, primary_key=True)
    txTime = Column(BigInteger, nullable=True)
    rxTime = Column(BigInteger, nullable=True)
    fromId = Column(BigInteger, nullable=False)
    toId = Column(BigInteger, nullable=False)
    tracerouteDetails = Column(JSON, default=None)
    snrAvg = Column(Float, default=None)
    directConnection = Column(Boolean, default=False)


class MessageHistory(Base):
    __tablename__ = 'message_history'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(BigInteger, nullable=False)
    fromId = Column(BigInteger, nullable=False)
    toId = Column(BigInteger, nullable=False)
    portnum = Column(String(length=75), nullable=False)
    packetRaw = Column(JSON, nullable=False)
    rxSnr = Column(Float, default=None)
    rxRssi = Column(Integer, default=None)


class Neighbor(Base):
    __tablename__ = 'neighbors'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    sourceNodeId = Column(BigInteger, nullable=False)
    neighborNodeId = Column(BigInteger, nullable=False)
    snr = Column(Float, nullable=False)


class NodeAlarmStatus(Base):
    __tablename__ = "node_alarm_status"
    nodeNum = Column(BigInteger, nullable=False, primary_key=True)
    temperatureAlarm = Column(Boolean, default=False)
    humidityAlarm = Column(Boolean, default=False)
    channelUsageAlarm = Column(Boolean, default=False)
    batteryLevelAlarm = Column(Boolean, default=False)
    networkPathAlarm = Column(Boolean, default=False)
    errorRateAlarm = Column(Boolean, default=False)


class Subscriptions(Base):
    __tablename__ = 'subscriptions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    # no foreign key here because the nodeNum is not guaranteed to be in the nodes table
    nodeNum = Column(BigInteger, nullable=False)
    isSubscribed = Column(Boolean, default=True)
    timestamp = Column(Integer, default=int(time()))

class OutgoingNotifications(Base):
    __tablename__ = 'outgoing_notifications'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer, nullable=False)
    toId = Column(BigInteger, nullable=False)
    message = Column(String(length=200), nullable=False)
    received = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)
    txId = Column(BigInteger, default=None) # id of the notification message sent to the node


class Waypoints(Base):
    __tablename__ = 'waypoints'
    id = Column(BigInteger, primary_key=True)
    name = Column(String(length=30), nullable=False)
    description = Column(String(length=100), default=None)
    icon = Column(BigInteger, nullable=False)
    latitudeI = Column(BigInteger, default=None)
    longitudeI = Column(BigInteger, default=None)
