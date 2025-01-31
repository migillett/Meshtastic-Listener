import logging
from time import time
import json

from meshtastic_listener.data_structures import NodeBase, DeviceMetrics

import sqlalchemy
from sqlalchemy.orm import sessionmaker, declarative_base


logger = logging.getLogger(__name__)

Base = declarative_base()


class Annoucement(Base):
    __tablename__ = 'annoucements'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    rxTime = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    fromId = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    toId = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    fromName = sqlalchemy.Column(sqlalchemy.String, default=None)
    message = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    rxSnr = sqlalchemy.Column(sqlalchemy.Float, nullable=False)
    rxRssi = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    hopStart = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    hopLimit = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    readCount = sqlalchemy.Column(sqlalchemy.Integer, default=0)
    isDeleted = sqlalchemy.Column(sqlalchemy.Integer, default=0)

    def __repr__(self):
        return f'<Annoucement(id={self.id}, rxTime={self.rxTime}, fromId={self.fromId}, toId={self.toId}, fromName={self.fromName}, message={self.message}, rxSnr={self.rxSnr}, rxRssi={self.rxRssi}, hopStart={self.hopStart}, hopLimit={self.hopLimit}, readCount={self.readCount}, isDeleted={self.isDeleted})>'


class Node(Base):
    __tablename__ = 'nodes'

    num = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    longName = sqlalchemy.Column(sqlalchemy.String, default=None)
    shortName = sqlalchemy.Column(sqlalchemy.String, default=None)
    macaddr = sqlalchemy.Column(sqlalchemy.String, default=None)
    hwModel = sqlalchemy.Column(sqlalchemy.String, default=None)
    publicKey = sqlalchemy.Column(sqlalchemy.String, default=None)
    role = sqlalchemy.Column(sqlalchemy.String, default=None)
    lastHeard = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    hopsAway = sqlalchemy.Column(sqlalchemy.Integer, default=None)

    def __repr__(self):
        return f'<Node(num={self.num}, longName={self.longName}, shortName={self.shortName}, macaddr={self.macaddr}, hwModel={self.hwModel}, publicKey={self.publicKey}, role={self.role}, lastHeard={self.lastHeard}, hopsAway={self.hopsAway})>'


class Metric(Base):
    __tablename__ = 'metrics'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    rxTime = sqlalchemy.Column(sqlalchemy.Integer, default=int(time()))
    nodeNum = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    batteryLevel = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    voltage = sqlalchemy.Column(sqlalchemy.Float, default=None)
    channelUtilization = sqlalchemy.Column(sqlalchemy.Float, default=None)
    airUtilTx = sqlalchemy.Column(sqlalchemy.Float, default=None)
    uptimeSeconds = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numPacketsTx = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numPacketsRx = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numPacketsRxBad = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numOnlineNodes = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numTotalNodes = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numRxDupe = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numTxRelay = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    numTxRelayCanceled = sqlalchemy.Column(sqlalchemy.Integer, default=None)
    
    def __repr__(self):
        return f'<Metric(id={self.id}, rxTime={self.rxTime}, nodeNum={self.nodeNum}, batteryLevel={self.batteryLevel}, voltage={self.voltage}, channelUtilization={self.channelUtilization}, airUtilTx={self.airUtilTx}, uptimeSeconds={self.uptimeSeconds}, numPacketsTx={self.numPacketsTx}, numPacketsRx={self.numPacketsRx}, numPacketsRxBad={self.numPacketsRxBad}, numOnlineNodes={self.numOnlineNodes}, numTotalNodes={self.numTotalNodes}, numRxDupe={self.numRxDupe}, numTxRelay={self.numTxRelay}, numTxRelayCanceled={self.numTxRelayCanceled})>'


class Traceroute(Base):
    __tablename__ = 'traceroutes'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    rxTime = sqlalchemy.Column(sqlalchemy.Integer, default=int(time()))
    fromId = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    toId = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    tracerouteDetails = sqlalchemy.Column(sqlalchemy.String, default=None)
    snrAvg = sqlalchemy.Column(sqlalchemy.Float, default=None)
    directConnection = sqlalchemy.Column(sqlalchemy.Boolean, default=False)

    def __repr__(self):
        return f'<Traceroute(id={self.id}, rxTime={self.rxTime}, fromId={self.fromId}, toId={self.toId}, tracerouteDetails={self.tracerouteDetails}, snrAvg={self.snrAvg}, directConnection={self.directConnection})>'


class MessageHistory(Base):
    __tablename__ = 'message_history'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    rxTime = sqlalchemy.Column(sqlalchemy.Integer, default=int(time()))
    fromId = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    toId = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    portnum = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    decoded = sqlalchemy.Column(sqlalchemy.String, nullable=False)

    def __repr__(self):
        return f'<MessageHistory(id={self.id}, rxTime={self.rxTime}, fromId={self.fromId}, toId={self.toId}, portnum={self.portnum}, decoded={self.decoded})>'


class ListenerDb:
    def __init__(self, db_path: str = ':memory:') -> None:
        self.db_path = db_path
        self.engine = sqlalchemy.create_engine(f'sqlite:///{self.db_path}')
        self.session = sessionmaker(bind=self.engine)
        self.create_tables()

    def create_tables(self) -> None:
        Base.metadata.create_all(self.engine)

    def insert_annoucement(self, payload: dict) -> None:
        session = self.session()
        session.add(Annoucement(
            rxTime=payload['rxTime'],
            fromId=payload['fromId'],
            toId=payload['toId'],
            fromName=payload['fromName'],
            message=payload['message'],
            rxSnr=payload['rxSnr'],
            rxRssi=payload['rxRssi'],
            hopStart=payload['hopStart'],
            hopLimit=payload['hopLimit'],
        ))
        session.commit()
        session.close()
        logging.info(f'Annoucement inserted into db: {payload}')

    def mark_annoucement_read(self, annoucement_ids: list[int]) -> None:
        with self.session() as session:
            session.query(Annoucement).filter(
                Annoucement.id.in_(annoucement_ids)
            ).update(
                {Annoucement.readCount: Annoucement.readCount + 1})
            session.commit()

    def get_annoucements(self, days_past: int = 7) -> list[Annoucement]:
        with self.session() as session:
            look_back = int(time()) - (days_past * 24 * 3600)
            results = session.query(Annoucement).filter(Annoucement.rxTime > look_back).all()
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
                session.add(Node(
                    num=node.num,
                    longName=node.user.longName,
                    shortName=node.user.shortName,
                    macaddr=node.user.macaddr,
                    hwModel=node.user.hwModel,
                    publicKey=node.user.publicKey,
                    role=node.user.role,
                    lastHeard=node.lastHeard,
                    hopsAway=node.hopsAway,
                ))
            session.commit()

    def get_node(self, node_num: int) -> Node:
        with self.session() as session:
            return session.query(Node).filter(Node.num == node_num).first()
        
    def get_shortname(self, node_num: int) -> str:
        node = self.get_node(node_num)
        if not node:
            return str(node_num)
        return node.shortName
    
    def insert_metrics(self, node_num: int, metrics: DeviceMetrics) -> None:
        with self.session() as session:
            session.add(Metric(
                nodeNum=node_num,
                batteryLevel=metrics.batteryLevel,
                voltage=metrics.voltage,
                channelUtilization=metrics.channelUtilization,
                airUtilTx=metrics.airUtilTx,
                uptimeSeconds=metrics.uptimeSeconds,
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

    def insert_traceroute(
            self,
            fromId: str,
            toId: str,
            traceroute_dict: dict,
            snr_avg: float,
            direct_connection: bool) -> None:
        with self.session() as session:
            session.add(Traceroute(
                fromId=fromId,
                toId=toId,
                tracerouteDetails=json.dumps(traceroute_dict, default=str, indent=2),
                snrAvg=snr_avg,
                directConnection=direct_connection,
            ))
            session.commit()

    def upsert_position(self, node_num: int, last_heard: int, latitude: float, longitude: float, altitude: float, precision_bits: int) -> None:
        with self.session() as session:
            node = self.get_node(node_num)
            node.lastHeard = last_heard
            node.latitude = latitude
            node.longitude = longitude
            node.altitude = altitude
            node.precisionBits = precision_bits
            session.commit()

    def insert_message_history(self, packet: dict) -> None:
        with self.session() as session:
            session.add(MessageHistory(
                rxTime=packet['rxTime'],
                fromId=packet['fromId'],
                toId=packet['toId'],
                portnum=packet['decoded']['portnum'],
                decoded=json.dumps(packet['decoded'], default=str, indent=2),
            ))
            session.commit()
