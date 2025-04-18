import logging
from time import time
import json
from statistics import mean

from meshtastic_listener.data_structures import (
    NodeBase, DevicePayload, TransmissionPayload,
    EnvironmentPayload, MessageReceived, NeighborSnr,
    WaypointPayload
)
from meshtastic_listener.listener_db.db_tables import (
    Base, Node, BulletinBoardMessage, BulletinBoardCategory,
    DeviceMetrics, TransmissionMetrics, EnvironmentMetrics,
    Traceroute, DbHashTable, MessageHistory, OutgoingNotifications,
    Subscriptions, Lockout, Neighbor, Waypoints, Subscriptions, AdminNodes
)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import Insert
from sqlalchemy.exc import IntegrityError
import xxhash

logger = logging.getLogger(__name__)


class ItemNotFound(Exception):
    pass

class InvalidCategory(Exception):
    pass


class ListenerDb:
    def __init__(
            self,
            hostname: str,
            username: str,
            password: str,
            db_name: str = 'listener_db',
            port: int = 5432,
            default_categories: list[str] = ['General', 'Annoucements']
        ) -> None:

        self.engine = create_engine(f'postgresql://{username}:{password}@{hostname}:{port}/{db_name}')
        self.session = sessionmaker(bind=self.engine)
        self.create_tables()
        self.create_default_categories(default_categories)
        self.hash_bbs_state()
        logger.info(f'Connected to postgres database: {hostname}/{db_name}')

    def create_tables(self) -> None:
        Base.metadata.create_all(self.engine)

    ### HASHING FUNCTIONS ###
    def hash_bbs_state(self) -> None:
        """
        Takes the DB's state and saves it to a hash for quick comparison to see if anything has changed in the database.

        This will eventually be used to synchronize the state of the database with other instances.
        """
        with self.session() as session:
            hash = xxhash.xxh64()
            for bbs_message in session.query(BulletinBoardMessage).all():
                hash.update(str(bbs_message.messageHash).encode('utf-8'))
            db_state = hash.hexdigest()

            last_hash = self.get_latest_db_hash()
            if last_hash is not None and last_hash.hash_value == db_state:
                # this happens sometimes when we reboot the listener and there are no new messages or changes to the database
                logger.debug('No change in database state.')
                return

            session.add(
                DbHashTable(
                    hash_value=db_state,
                    timestamp=int(time())
                )
            )
            session.commit()

    def get_latest_db_hash(self) -> DbHashTable | None:
        '''
        Retrieves the latest hash of the database state from the `db_state_hash_table`.
        This is used to check if the database state has changed since the last time it was hashed.
        '''
        with self.session() as session:
            # Get the most recent hash from the db_state_hash_table
            last_hash = session.query(DbHashTable).order_by(DbHashTable.timestamp.desc()).first()
            if last_hash:
                return last_hash
            else:
                logger.warning('No hash found in db_state_hash_table.')
                return None
            
    def get_hash_timestamp(self, hash_string: str) -> int:
        '''
        Used for synching database states. This will return the timestamp of a given hash value in the `db_state_hash_table`.
        '''
        with self.session() as session:
            # Get the timestamp of the given hash value
            hash_entry = session.query(DbHashTable).filter(DbHashTable.hash_value == hash_string).first()
            if hash_entry:
                return hash_entry.timestamp
            else:
                logger.warning(f'No timestamp found for hash value: {hash_string}')
                return 0
    
    ### MESSAGES ###
    def post_bbs_message(self, payload: MessageReceived, category_id: int = 1) -> None:
        with self.session() as session:
            msg_hash = xxhash.xxh64(f"{payload.decoded.text}{payload.fromId}{payload.rxTime}").hexdigest()
            session.add(BulletinBoardMessage(
                rxTime=payload.rxTime,
                fromId=payload.fromId,
                toId=payload.toId,
                message=payload.decoded.text,
                categoryId=category_id,
                rxSnr=payload.rxSnr,
                rxRssi=payload.rxRssi,
                hopStart=payload.hopStart,
                hopLimit=payload.hopLimit,
                messageHash=msg_hash
            ))
            session.commit()
        self.hash_bbs_state()

    def mark_bbs_message_read(self, bbs_message_ids: list[int]) -> None:
        with self.session() as session:
            session.query(BulletinBoardMessage).filter(
                BulletinBoardMessage.id.in_(bbs_message_ids)
            ).update(
                {BulletinBoardMessage.readCount: BulletinBoardMessage.readCount + 1})
            session.commit()

    def get_bbs_messages(self, days_past: int = 7, category_id: int = 1) -> list[BulletinBoardMessage]:
        with self.session() as session:
            look_back = int(time() - (days_past * 24 * 3600))
            results = session.query(BulletinBoardMessage).filter(
                BulletinBoardMessage.rxTime > look_back,
                BulletinBoardMessage.isDeleted == False,
                BulletinBoardMessage.categoryId == category_id
            ).all()

            logger.info(f'Found {len(results)} bbs messages from the last {days_past} days in category {category_id}')
            [self.mark_bbs_message_read([result.id]) for result in results]
            return results
            
    def soft_delete_bbs_messages(self) -> None:
        with self.session() as session:
            session.query(BulletinBoardMessage).filter(
                BulletinBoardMessage.isDeleted == False
            ).update({BulletinBoardMessage.isDeleted: 1})
            session.commit()

    ### CATEGORIES ###
    def create_default_categories(self, categories: list[str]) -> None:
        logger.info(f'Creating BBS categories: {categories}')
        with self.session() as session:
            existing_categories = session.query(BulletinBoardCategory).all()
            for category in categories:
                if category not in [cat.name for cat in existing_categories]:
                    session.add(BulletinBoardCategory(name=category))
            session.commit()

    def list_categories(self) -> list[BulletinBoardCategory]:
        with self.session() as session:
            return session.query(
                BulletinBoardCategory
            ).order_by(
                BulletinBoardCategory.id.asc()
            ).all()
        
    def get_category_by_id(self, category_id: int) -> BulletinBoardCategory:
        with self.session() as session:
            return session.query(
                BulletinBoardCategory
            ).filter(
                BulletinBoardCategory.id == category_id
            ).first()
        
    def get_category_by_name(self, category_name: str) -> BulletinBoardCategory:
        with self.session() as session:
            return session.query(
                BulletinBoardCategory
            ).filter(
                BulletinBoardCategory.name == category_name.title()
            ).first()
        
    def select_category(self, node_num: int, category_id: int) -> list[BulletinBoardMessage]:
        '''
        Allows user to select a category and automatically returns the messages in that category.
        '''
        try:
            with self.session() as session:
                node = self.get_node(node_num)
                if not node:
                    # TODO - might need to add a way to add the node to the db if we've never heard them before
                    raise ItemNotFound(f'Node {node_num} not found in db. Unable to update category.')
                node.selectedCategory = category_id
                session.add(node)
                session.commit()

                return self.get_bbs_messages(category_id=category_id)

        except IntegrityError:
            raise InvalidCategory(f'Category {category_id} does not exist.')

    ### NODES ###
    def insert_nodes(self, nodes: list[NodeBase]) -> None:
        with self.session() as session:
            for node in nodes:
                stmt = Insert(Node).values(
                    nodeNum=node.num,
                    longName=node.user.longName,
                    shortName=node.user.shortName,
                    macAddr=node.user.macaddr,
                    hwModel=node.user.hwModel,
                    publicKey=node.user.publicKey,
                    nodeRole=node.user.role,
                    lastHeard=node.lastHeard,
                    hopsAway=node.hopsAway,
                ).on_conflict_do_update(
                    index_elements=['nodeNum'],
                    set_={
                        'longName': node.user.longName,
                        'shortName': node.user.shortName,
                        'macAddr': node.user.macaddr,
                        'hwModel': node.user.hwModel,
                        'publicKey': node.user.publicKey,
                        'nodeRole': node.user.role,
                        'lastHeard': node.lastHeard,
                        'hopsAway': node.hopsAway,
                    }
                )

                session.execute(stmt)

            session.commit()
            logger.debug(f'Successfully upserted {len(nodes)} nodes into db')

    def get_node_selected_category(self, node_num: int) -> BulletinBoardCategory:
        with self.session() as session:
            return session.query(BulletinBoardCategory).join(
                Node, BulletinBoardCategory.id == Node.selectedCategory
            ).filter(
                Node.nodeNum == node_num
            ).first()

    def get_node(self, node_num: int) -> Node:
        with self.session() as session:
            return session.query(Node).filter(Node.nodeNum == node_num).first()
        
    def get_closest_nodes(self, n_nodes: int = 5) -> list[Node]:
        with self.session() as session:
            nodes = session.query(Node).filter(Node.distance.isnot(None), Node.distance > 0).order_by(Node.distance).limit(n_nodes).all()
            return nodes

    def get_shortname(self, node_num: int) -> str:
        node = self.get_node(node_num)
        if not node:
            return str(node_num)
        return node.shortName
    
    ### ADMIN NODES ###
    def is_admin_node(self, node_num: int) -> bool:
        with self.session() as session:
            admin_node = session.query(AdminNodes).filter(AdminNodes.nodeNum == node_num).first()
            return admin_node is not None
        
    def get_active_admin_nodes(self) -> list[AdminNodes]:
        with self.session() as session:
            return session.query(AdminNodes).filter(AdminNodes.enabled == True).all()
        
    def insert_admin_node(self, node_num: int) -> None:
        with self.session() as session:
            stmt = Insert(AdminNodes).values(
                nodeNum=node_num,
                timestamp=int(time())
            ).on_conflict_do_nothing()
            session.execute(stmt)
            session.commit()
    
    ### METRICS ###
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
                raise ItemNotFound(f'Node {node_num} not found in db. Unable to update position.')
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
            session.add(
                MessageHistory(
                    rxTime=rx_time,
                    fromId=from_id,
                    toId=to_id,
                    portnum=portnum,
                    rxSnr=packet_raw.get('rxSnr', None),
                    rxRssi=packet_raw.get('rxRssi', None),
                    packetRaw=packet_raw
                )
            )
            session.commit()

    def insert_neighbor(self, source_node_id: int, neighbor_id: int, snr: float, rx_time: int) -> None:
        with self.session() as session:
            logger.debug(f'Inserting neighbor: {neighbor_id} with SNR: {snr} for source node: {source_node_id} at time: {rx_time}')
            session.add(
                Neighbor(
                    rxTime=rx_time,
                    sourceNodeId=source_node_id,
                    neighborNodeId=neighbor_id,
                    snr=snr
                )
            )
            session.commit()

    ### NOTIFICATIONS ###
    def insert_notification(self, to_id: int, message: str) -> None:
        with self.session() as session:
            session.add(OutgoingNotifications(
                toId=to_id,
                message=message,
                timestamp=int(time()),
            ))
            session.commit()

    def get_pending_notifications(self, to_id: int, max_attempts: int = 5) -> list[OutgoingNotifications]:
        with self.session() as session:
            return session.query(
                OutgoingNotifications
            ).filter(
                OutgoingNotifications.toId == to_id,
                OutgoingNotifications.received == False,
                OutgoingNotifications.attempts < max_attempts
            ).all()

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

    def mark_notification_received(self, notif_tx_id: int) -> None:
        '''
        Takes the request_id from the packet and marks it as received by the end-user
        '''
        with self.session() as session:
            notification = session.query(
                OutgoingNotifications
            ).filter(
                OutgoingNotifications.txId == notif_tx_id
            ).first()
            if notification:
                logger.debug(f'Marking notification {notif_tx_id} as received.')
                notification.received = True
                session.add(notification)
                session.commit()

    ### SUBSCRIPTIONS ###
    def insert_subscription(self, node_num: int, category_id: int | None = None) -> None:
        '''
        Will raise IntegrityError if the categoryId is not valid.
        '''
        try:
            with self.session() as session:
                stmt = Insert(Subscriptions).values(
                    nodeNum=node_num,
                    categoryId=category_id,
                    isSubscribed=True,
                    timestamp=int(time())
                )
                session.execute(stmt)
                session.commit()
        except IntegrityError:
            raise InvalidCategory(f'Category {category_id} does not exist.')

    def unsubscribe_from_category(self, node_num: int, category_id: int | None = None) -> None:
        with self.session() as session:
            subscription = session.query(Subscriptions).filter(
                Subscriptions.nodeNum == node_num,
                Subscriptions.categoryId == category_id
            ).first()
            if subscription:
                session.delete(subscription)
                session.commit()
            else:
                logger.warning(f'No subscription found for node {node_num} in category {category_id}.')

    def unsubscribe_all(self, node_num: int) -> None:
        with self.session() as session:
            subscriptions = session.query(Subscriptions).filter(Subscriptions.nodeNum == node_num).all()
            for subscription in subscriptions:
                subscription.isSubscribed = False
                session.add(subscription)
            session.commit()

    def list_subscribers(self, category_id: int) -> list[int]:
        # returns a list of node numbers that are subscribed to the given category
        with self.session() as session:
            subscribers = session.query(Subscriptions.nodeNum).filter(
                Subscriptions.categoryId == category_id,
                Subscriptions.isSubscribed == True
            ).all()
            return [subscriber[0] for subscriber in subscribers]

    def list_user_subscriptions(self, node_num: int) -> list[tuple[int, str]]:
        with self.session() as session:
            subscriptions = session.query(
                Subscriptions.categoryId, BulletinBoardCategory.name
            ).join(
                BulletinBoardCategory, Subscriptions.categoryId == BulletinBoardCategory.id
            ).filter(
                Subscriptions.nodeNum == node_num,
                Subscriptions.isSubscribed == True
            ).order_by(
                Subscriptions.timestamp.desc()
            ).all()
            return subscriptions

    def has_active_subscriptions(self, node_num: int) -> bool:
        with self.session() as session:
            subscriptions = session.query(Subscriptions).filter(
                Subscriptions.nodeNum == node_num,
                Subscriptions.isSubscribed == True
            ).all()
            return len(subscriptions) > 0

    def is_subscribed(self, node_num: int, category_id: int | None = None) -> bool:
        with self.session() as session:
            subscription = session.query(Subscriptions).filter(
                Subscriptions.nodeNum == node_num,
                Subscriptions.categoryId == category_id
            ).first()
            if subscription:
                return subscription.isSubscribed
            return False

    ### LOCKOUTS ###
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

    ### WAYPOINTS ###
    def insert_waypoint(self, waypoint: WaypointPayload) -> None:
        with self.session() as session:
            stmt = Insert(Waypoints).values(
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
                    'longitudeI': waypoint.longitudeI
                }
            )
            session.execute(stmt)
            session.commit()

    def get_waypoints(self) -> list[Waypoints]:
        with self.session() as session:
            return session.query(Waypoints).all()
