import logging
from time import time
import json

from meshtastic_listener.data_structures import (
    NodeBase, DevicePayload, TransmissionPayload, EnvironmentPayload, MessageReceived
)

from sqlalchemy import Column, Integer, String, Float, Boolean, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.sqlite import insert


logger = logging.getLogger(__name__)

Base = declarative_base()


class Annoucement(Base):
    __tablename__ = 'annoucements'

    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    fromId = Column(Integer, nullable=False)
    toId = Column(Integer, nullable=False)
    message = Column(String, nullable=False)
    rxSnr = Column(Float, nullable=False)
    rxRssi = Column(Integer, nullable=False)
    hopStart = Column(Integer, nullable=False)
    hopLimit = Column(Integer, nullable=False)
    readCount = Column(Integer, default=0)
    isDeleted = Column(Integer, default=0)

    def __repr__(self):
        return f'<Annoucement(id={self.id}, rxTime={self.rxTime}, fromId={self.fromId}, toId={self.toId}, message={self.message}, rxSnr={self.rxSnr}, rxRssi={self.rxRssi}, hopStart={self.hopStart}, hopLimit={self.hopLimit}, readCount={self.readCount}, isDeleted={self.isDeleted})>'

class Node(Base):
    __tablename__ = 'nodes'

    num = Column(Integer, primary_key=True)
    longName = Column(String, default=None)
    shortName = Column(String, default=None)
    macaddr = Column(String, default=None)
    hwModel = Column(String, default=None)
    publicKey = Column(String, default=None)
    role = Column(String, default=None)
    lastHeard = Column(Integer, default=None)
    latitude = Column(Float, default=None)
    longitude = Column(Float, default=None)
    altitude = Column(Float, default=None)
    precisionBits = Column(Integer, default=None)
    hopsAway = Column(Integer, default=None)

    def __repr__(self):
        return f'<Node(num={self.num}, longName={self.longName}, shortName={self.shortName}, macaddr={self.macaddr}, hwModel={self.hwModel}, publicKey={self.publicKey}, role={self.role}, lastHeard={self.lastHeard}, latitude={self.latitude}, longitude={self.longitude}, altitude={self.altitude}, precisionBits={self.precisionBits}, hopsAway={self.hopsAway})>'

class DeviceMetrics(Base):
    __tablename__ = 'device_metrics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    nodeNum = Column(Integer, nullable=False)
    batteryLevel = Column(Integer, default=None)
    voltage = Column(Float, default=None)
    channelUtilization = Column(Float, default=None)
    uptimeSeconds = Column(Integer, default=None)

    def __repr__(self):
        return f'<DeviceMetrics(id={self.id}, rxTime={self.rxTime}, nodeNum={self.nodeNum}, batteryLevel={self.batteryLevel}, voltage={self.voltage}, channelUtilization={self.channelUtilization}, uptimeSeconds={self.uptimeSeconds})>'
    
class TransmissionMetrics(Base):
    __tablename__ = 'transmission_metrics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    nodeNum = Column(Integer, nullable=False)
    airUtilTx = Column(Float, default=None)
    numPacketsTx = Column(Integer, default=None)
    numPacketsRx = Column(Integer, default=None)
    numPacketsRxBad = Column(Integer, default=None)
    numOnlineNodes = Column(Integer, default=None)
    numTotalNodes = Column(Integer, default=None)
    numRxDupe = Column(Integer, default=None)
    numTxRelay = Column(Integer, default=None)
    numTxRelayCanceled = Column(Integer, default=None)

    def __repr__(self):
        return f'<TransmissionMetrics(id={self.id}, rxTime={self.rxTime}, nodeNum={self.nodeNum}, airUtilTx={self.airUtilTx}, numPacketsTx={self.numPacketsTx}, numPacketsRx={self.numPacketsRx}, numPacketsRxBad={self.numPacketsRxBad}, numOnlineNodes={self.numOnlineNodes}, numTotalNodes={self.numTotalNodes}, numRxDupe={self.numRxDupe}, numTxRelay={self.numTxRelay}, numTxRelayCanceled={self.numTxRelayCanceled})>'


class EnvironmentMetrics(Base):
    __tablename__ = 'environment_metrics'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    nodeNum = Column(Integer, nullable=False)
    temperature = Column(Float, default=None)
    relativeHumidity = Column(Float, default=None)
    barometricPressure = Column(Float, default=None)
    gasResistance = Column(Float, default=None)
    iaq = Column(Integer, default=None)

    def __repr__(self):
        return f'<EnvironmentMetrics(id={self.id}, rxTime={self.rxTime}, nodeNum={self.nodeNum}, temperature={self.temperature}, relativeHumidity={self.relativeHumidity}, barometricPressure={self.barometricPressure}, gasResistance={self.gasResistance}, iaq={self.iaq})>'


class Traceroute(Base):
    __tablename__ = 'traceroutes'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    fromId = Column(Integer, nullable=False)
    toId = Column(Integer, nullable=False)
    tracerouteDetails = Column(String, default=None)
    snrAvg = Column(Float, default=None)
    directConnection = Column(Boolean, default=False)

    def __repr__(self):
        return f'<Traceroute(id={self.id}, rxTime={self.rxTime}, fromId={self.fromId}, toId={self.toId}, tracerouteDetails={self.tracerouteDetails}, snrAvg={self.snrAvg}, directConnection={self.directConnection})>'


class MessageHistory(Base):
    __tablename__ = 'message_history'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    fromId = Column(Integer, nullable=False)
    toId = Column(Integer, nullable=False)
    portnum = Column(String, nullable=False)
    packetRaw = Column(String, nullable=False)

    def __repr__(self):
        return f'<MessageHistory(id={self.id}, rxTime={self.rxTime}, fromId={self.fromId}, toId={self.toId}, portnum={self.portnum}, packetRaw={self.packetRaw})>'


class Neighbor(Base):
    __tablename__ = 'neighbors'
    id = Column(Integer, primary_key=True, autoincrement=True)
    rxTime = Column(Integer, nullable=False)
    sourceNodeId = Column(Integer, nullable=False)
    neighborNodeId = Column(Integer, nullable=False)
    snr = Column(Float, nullable=False)


class ListenerDb:
    def __init__(self, db_path: str = ':memory:') -> None:
        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{self.db_path}')
        self.session = sessionmaker(bind=self.engine)
        self.create_tables()

    def create_tables(self) -> None:
        Base.metadata.create_all(self.engine)

    def insert_annoucement(self, payload: MessageReceived) -> None:
        session = self.session()
        session.add(Annoucement(
            rxTime=payload.rxTime,
            fromId=payload.fromId,
            toId=payload.toId,
            message=payload.decoded.text,
            rxSnr=payload.rxSnr,
            rxRssi=payload.rxRssi,
            hopStart=payload.hopStart,
            hopLimit=payload.hopLimit,
        ))
        session.commit()
        session.close()

    def mark_annoucement_read(self, annoucement_ids: list[int]) -> None:
        with self.session() as session:
            session.query(Annoucement).filter(
                Annoucement.id.in_(annoucement_ids)
            ).update(
                {Annoucement.readCount: Annoucement.readCount + 1})
            session.commit()

    def get_annoucements(self, days_past: int = 7) -> list[Annoucement]:
        with self.session() as session:
            look_back = int(time() - (days_past * 24 * 3600))
            results = session.query(Annoucement).filter(
                Annoucement.rxTime > look_back,
                Annoucement.isDeleted == 0
            ).all()
            logger.info(f'Found {len(results)} annoucements from the last {days_past} days')
            [self.mark_annoucement_read([result.id]) for result in results]
            return results
            
    def soft_delete_annoucements(self) -> None:
        with self.session() as session:
            session.query(Annoucement).filter(
                Annoucement.isDeleted == 0
            ).update({Annoucement.isDeleted: 1})
            session.commit()

    def insert_nodes(self, nodes: list[NodeBase]) -> None:
        with self.session() as session:
            for node in nodes:
                stmt = insert(Node).values(
                    num=node.num,
                    longName=node.user.longName,
                    shortName=node.user.shortName,
                    macaddr=node.user.macaddr,
                    hwModel=node.user.hwModel,
                    publicKey=node.user.publicKey,
                    role=node.user.role,
                    lastHeard=node.lastHeard,
                    hopsAway=node.hopsAway,
                ).on_conflict_do_update(
                    index_elements=['num'],
                    set_={
                        'longName': node.user.longName,
                        'shortName': node.user.shortName,
                        'macaddr': node.user.macaddr,
                        'hwModel': node.user.hwModel,
                        'publicKey': node.user.publicKey,
                        'role': node.user.role,
                        'lastHeard': node.lastHeard,
                        'hopsAway': node.hopsAway,
                    }
                )
                
                session.execute(stmt)

            session.commit()
            logger.debug(f'Successfully upserted {len(nodes)} nodes into db')

    def get_node(self, node_num: int) -> Node:
        with self.session() as session:
            return session.query(Node).filter(Node.num == node_num).first()
        
    def get_shortname(self, node_num: int) -> str:
        node = self.get_node(node_num)
        if not node:
            return str(node_num)
        return node.shortName
    
    def insert_device_metrics(self, node_num: int, rxTime: int, metrics: DevicePayload) -> None:
        with self.session() as session:
            session.add(DeviceMetrics(
                nodeNum=node_num,
                rxTime=rxTime,
                batteryLevel=metrics.batteryLevel,
                voltage=metrics.voltage,
                channelUtilization=metrics.channelUtilization,
                uptimeSeconds=metrics.uptimeSeconds,
            ))
            session.commit()

    def insert_transmission_metrics(self, node_num: int, rxTime: int, metrics: TransmissionPayload) -> None:
        with self.session() as session:
            session.add(TransmissionMetrics(
                nodeNum=node_num,
                rxTime=rxTime,
                airUtilTx=metrics.airUtilTx,
                numPacketsTx=metrics.numPacketsTx,
                numPacketsRx=metrics.numPacketsRx,
                numPacketsRxBad=metrics.numPacketsRxBad,
                numOnlineNodes=metrics.numOnlineNodes,
                numTotalNodes=metrics.numTotalNodes,
                numRxDupe=metrics.numRxDupe,
                numTxRelay=metrics.numTxRelay,
                numTxRelayCanceled=metrics.numTxRelayCanceled,
            ))
            session.commit()
    
    def insert_environment_metrics(self, node_num: int, rxTime: int, metrics: EnvironmentPayload) -> None:
        with self.session() as session:
            session.add(EnvironmentMetrics(
                nodeNum=node_num,
                rxTime=rxTime,
                temperature=metrics.temperature,
                relativeHumidity=metrics.relativeHumidity,
                barometricPressure=metrics.barometricPressure,
                gasResistance=metrics.gasResistance,
                iaq=metrics.iaq,
            ))
            session.commit()

    def insert_traceroute(
            self,
            fromId: str,
            toId: str,
            rxTime: int,
            traceroute_dict: dict,
            snr_avg: float,
            direct_connection: bool) -> None:
        with self.session() as session:
            session.add(Traceroute(
                rxTime=rxTime,
                fromId=fromId,
                toId=toId,
                tracerouteDetails=json.dumps(traceroute_dict, default=str, indent=2),
                snrAvg=snr_avg,
                directConnection=direct_connection,
            ))
            session.commit()

    def upsert_position(
            self,
            node_num: int,
            last_heard: int,
            latitude: float,
            longitude: float,
            altitude: float,
            precision_bits: int) -> None:
        with self.session() as session:
            node = self.get_node(node_num)
            if not node:
                logger.error(f'Node {node_num} not found in db. Unable to update position.')
                return
            node.lastHeard = last_heard
            node.latitude = latitude
            node.longitude = longitude
            node.altitude = altitude
            node.precisionBits = precision_bits
            session.add(node)
            session.commit()

    def insert_message_history(self, rx_time: int, from_id: int, to_id: int, portnum: str, packet_raw: dict) -> None:
        with self.session() as session:
            session.add(MessageHistory(
                rxTime=rx_time,
                fromId=from_id,
                toId=to_id,
                portnum=portnum,
                packetRaw=json.dumps(packet_raw, default=str, indent=2)
            ))
            session.commit()

    def insert_neighbor(self, source_node_id: int, neighbor_id: str, snr: float, rx_time: int) -> None:
        with self.session() as session:
            session.add(Neighbor(
                sourceNodeId=source_node_id,
                neighborNodeId=neighbor_id,
                snr=snr,
                rxTime=rx_time,
            ))
            session.commit()
