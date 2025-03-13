import logging
from time import time
import json
from statistics import mean

from meshtastic_listener.data_structures import (
    NodeBase, DevicePayload, TransmissionPayload,
    EnvironmentPayload, MessageReceived, NeighborSnr,
    WaypointPayload
)

from sqlalchemy import Column, Integer, String, Float, Boolean, create_engine, func
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.sqlite import insert


logger = logging.getLogger(__name__)

Base = declarative_base()

class ItemNotFound(Exception):
    pass


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
    distance = Column(Float, default=None)
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
    rxSnr = Column(Float, default=None)
    rxRssi = Column(Integer, default=None)

    def __repr__(self):
        return f'<MessageHistory(id={self.id}, rxTime={self.rxTime}, fromId={self.fromId}, toId={self.toId}, portnum={self.portnum}, packetRaw={self.packetRaw})>'

class OutgoingNotifications(Base):
    __tablename__ = 'outgoing_notifications'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer, nullable=False)
    toId = Column(Integer, nullable=False)
    message = Column(String, nullable=False)
    received = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)
    txId = Column(Integer, default=None) # id of the notification message sent to the node

    def __repr__(self):
        return f'<OutgoingNotifications(id={self.id}, timestamp={self.timestamp}, toId={self.toId}, message={self.message}, received={self.received}, attempts={self.attempts})>'


class Lockout(Base):
    __tablename__ = 'node_lockout'
    nodeNum = Column(Integer, primary_key=True)
    failedAttempts = Column(Integer, default=0)
    lastFailedAttempt = Column(Integer, default=0)
    locked = Column(Boolean, default=False)

    def __repr__(self):
        return f'<Lockout(nodeNum={self.nodeNum}, failedAttempts={self.failedAttempts}, lastFailedAttempt={self.lastFailedAttempt}, locked={self.locked})>'


class Waypoints(Base):
    __tablename__ = 'waypoints'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, default=None)
    icon = Column(Integer, nullable=False)
    latitudeI = Column(Integer, default=None)
    longitudeI = Column(Integer, default=None)

    def __repr__(self):
        return f'<Waypoints(id={self.id}, name={self.name}, description={self.description}, icon={self.icon}, latitudeI={self.latitudeI}, longitudeI={self.longitudeI})>'


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
        
    def get_closest_nodes(self, n_nodes: int = 5) -> list[Node]:
        with self.session() as session:
            nodes = session.query(Node).filter(Node.distance.isnot(None), Node.distance > 0).order_by(Node.distance).limit(n_nodes).all()
            return nodes

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
            distance: float,
            precision_bits: int) -> None:
        with self.session() as session:
            node = self.get_node(node_num)
            if not node:
                logger.warning(f'Node {node_num} not found in db. Unable to update position.')
                return
            node.lastHeard = last_heard
            node.latitude = latitude
            node.longitude = longitude
            node.altitude = altitude
            node.precisionBits = precision_bits
            node.distance = distance
            session.add(node)
            session.commit()

    def insert_message_history(self, rx_time: int, from_id: int, to_id: int, portnum: str, packet_raw: dict) -> None:
        with self.session() as session:
            session.add(MessageHistory(
                rxTime=rx_time,
                fromId=from_id,
                toId=to_id,
                portnum=portnum,
                rxSnr=packet_raw.get('rxSnr', None),
                rxRssi=packet_raw.get('rxRssi', None),
                packetRaw=json.dumps(packet_raw, default=str, indent=2),
            ))
            session.commit()

    def insert_notification(self, to_id: int, message: str) -> None:
        with self.session() as session:
            session.add(OutgoingNotifications(
                toId=to_id,
                message=message,
                timestamp=int(time()),
            ))
            session.commit()

    def get_pending_notifications(self, max_attempts: int = 5) -> list[OutgoingNotifications]:
        with self.session() as session:
            return session.query(OutgoingNotifications).filter(OutgoingNotifications.received == 0, OutgoingNotifications.attempts < max_attempts).all()

    def increment_notification_attempts(self, notification_id: int, notif_tx_id: int) -> None:
        """
        notification_id: the unique, auto-incremented value of the notificaiton in the db
        notif_tx_id: the unique message ID of the most recent notification message sent to the node
        """
        with self.session() as session:
            notif = session.query(OutgoingNotifications).filter(OutgoingNotifications.id == notification_id).first()
            if notif is not None:
                notif.txId = notif_tx_id
                notif.attempts = notif.attempts + 1
                session.add(notif)
                session.commit()
            else:
                raise ItemNotFound(f'Notification with id {notification_id} not found in db')
            
    def check_pending_notifications(self) -> bool:
        '''
        checks for any notifications that have been sent but not confirmed received by the end-user

        Returns True if there are pending notifications, False otherwise
        '''
        with self.session() as session:
            # check if received == 0 AND notif_xt_id is not None
            return session.query(OutgoingNotifications).filter(
                OutgoingNotifications.received == 0,
                OutgoingNotifications.txId.isnot(None)
            ).count() > 0

    def mark_notification_received(self, notif_tx_id: int) -> None:
        '''
        Takes the request_id from the packet and marks it as received by the end-user
        '''
        with self.session() as session:
            notification = session.query(OutgoingNotifications).filter(OutgoingNotifications.txId == notif_tx_id).first()
            if notification:
                notification.received = True
                session.add(notification)
                session.commit()

    def check_node_lockout(self, node_num: int) -> bool:
        with self.session() as session:
            lockout = session.query(Lockout).filter(Lockout.nodeNum == node_num).first()
            if lockout:
                return lockout.locked
            return False
        
    def increment_failed_attempts(self, node_num: int, lockout_n: int = 3) -> None:
        with self.session() as session:
            lockout = session.query(Lockout).filter(Lockout.nodeNum == node_num).first()
            if lockout:
                lockout.failedAttempts += 1
                lockout.lastFailedAttempt = int(time())
                if lockout.failedAttempts >= lockout_n:
                    logger.info(f'Node {node_num} has reached the failed attempt threshold. Locking out node.')
                    lockout.locked = True
                session.add(lockout)
                session.commit()
            else:
                session.add(Lockout(nodeNum=node_num, failedAttempts=1, lastFailedAttempt=int(time())))
                session.commit()

    def get_neighbors(self, lookback_hours: int = 72) -> list[NeighborSnr]:
        # check the message_history table for the most "talkative" nodes from the past n hours
        # order them by average SNR

        response: list[NeighborSnr] = []
        neighbors = {}

        with self.session() as session:
            messages = session.query(
                MessageHistory
            ).filter(
                MessageHistory.rxTime > int(time() - (lookback_hours * 3600))
            ).all()

            for message in messages:
                if isinstance(message.rxSnr, float):
                    if message.fromId in neighbors:
                        neighbors[message.fromId].append(message.rxSnr)
                    else:
                        neighbors[message.fromId] = [message.rxSnr]

        for neighbor in neighbors:
            response.append(
                NeighborSnr(
                    shortName=self.get_shortname(neighbor),
                    snr=round(mean(neighbors[neighbor]), 2)
                )
            )

        return sorted(response, key=lambda x: x.snr, reverse=True)

    def insert_waypoint(self, waypoint: WaypointPayload) -> None:
        with self.session() as session:
            stmt = insert(Waypoints).values(
                id=waypoint.id,
                name=waypoint.name,
                description=waypoint.description,
                icon=waypoint.icon,
                latitudeI=waypoint.latitudeI,
                longitudeI=waypoint.longitudeI,
            ).on_conflict_do_update(
                index_elements=['id'],
                set_={
                    'name': waypoint.name,
                    'description': waypoint.description,
                    'icon': waypoint.icon,
                    'latitudeI': waypoint.latitudeI,
                    'longitudeI': waypoint.longitudeI,
                }
            )
            session.execute(stmt)
            session.commit()

    def get_waypoint_categories(self) -> list[str]:
        with self.session() as session:
            return session.query(Waypoints.category).distinct().all()

    def get_waypoints(self) -> list[Waypoints]:
        with self.session() as session:
            return session.query(Waypoints).all()
