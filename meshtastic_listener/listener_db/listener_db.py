import logging
from time import time
from datetime import timedelta
from statistics import mean
from typing import Optional

from meshtastic_listener.data_structures import (
    NodeBase, DevicePayload, TransmissionPayload,
    EnvironmentPayload, WaypointPayload, NodeRoles,
    NodeAlerts
)
from meshtastic_listener.listener_db.db_tables import (
    Node, DeviceMetrics, TransmissionMetrics, EnvironmentMetrics,
    Traceroute, MessageHistory, OutgoingNotifications, Subscriptions,
    Neighbor, Waypoints, AdminNodes, NodeAlarmStatus
)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import Insert
from sqlalchemy import func
from time import time

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
            port: int = 5432
        ) -> None:

        self.engine = create_engine(f'postgresql://{username}:{password}@{hostname}:{port}/{db_name}')
        self.session = sessionmaker(bind=self.engine)
        logger.info(f'Connected to postgres database: {hostname}/{db_name}')

    ### NODES ###
    def insert_node(self, node: NodeBase) -> None:
        with self.session() as session:
            stmt = Insert(Node).values(
                    nodeNum=node.num,
                    longName=node.user.longName,
                    shortName=node.user.shortName,
                    macAddr=node.user.macaddr,
                    hwModel=node.user.hwModel,
                    publicKey=node.user.publicKey,
                    nodeRole=node.user.role,
                    latitude=node.position.latitude,
                    longitude=node.position.longitude,
                    altitude=node.position.altitude,
                    lastHeard=node.lastHeard,
                    hopsAway=node.hopsAway,
                    isHost=node.isHost,
                    isFavorite=node.isFavorite,
                    hostSoftwareVersion=node.hostSoftwareVersion,
                ).on_conflict_do_update(
                    index_elements=['nodeNum'],
                    set_={
                        'longName': node.user.longName,
                        'shortName': node.user.shortName,
                        'macAddr': node.user.macaddr,
                        'hwModel': node.user.hwModel,
                        'publicKey': node.user.publicKey,
                        'nodeRole': node.user.role,
                        'latitude': node.position.latitude,
                        'longitude': node.position.longitude,
                        'altitude': node.position.altitude,
                        'lastHeard': node.lastHeard,
                        'hopsAway': node.hopsAway,
                        'isHost': node.isHost,
                        'isFavorite': node.isFavorite,
                        'hostSoftwareVersion': node.hostSoftwareVersion,
                    }
                )
            session.execute(stmt)
            session.commit()
        logger.debug(f'Inserted node into DB: {node.model_dump_json()}')

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
                    latitude=node.position.latitude,
                    longitude=node.position.longitude,
                    altitude=node.position.altitude,
                    lastHeard=node.lastHeard,
                    isFavorite=node.isFavorite,
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
                        'latitude': node.position.latitude,
                        'longitude': node.position.longitude,
                        'altitude': node.position.altitude,
                        'lastHeard': node.lastHeard,
                        'hopsAway': node.hopsAway,
                        'isFavorite': node.isFavorite,
                    }
                )

                session.execute(stmt)

            session.commit()
            logger.debug(f'Successfully upserted {len(nodes)} nodes into db')

    def get_node(self, node_num: int) -> Node:
        with self.session() as session:
            return session.query(Node).filter(Node.nodeNum == node_num).first()
        
    def get_nodes(self, role: Optional[NodeRoles] = None, last_heard: int = 0) -> list[Node]:
        with self.session() as session:
            if role is not None:
                return session.query(
                    Node
                ).filter(
                    Node.nodeRole == role.value,
                    Node.lastHeard >= last_heard
                ).order_by(
                    Node.lastHeard.desc()
                ).all()
            else:
                return session.query(
                    Node
                ).filter(
                    Node.lastHeard >= last_heard
                ).order_by(
                    Node.lastHeard.desc()
                ).all()

    def get_shortname(self, node_num: int) -> str:
        node = self.get_node(node_num)
        if not node:
            return str(node_num)
        return str(node.shortName)
    
    def calculate_center_coordinates(self) -> tuple[float, float]:
        with self.session() as session:
            nodes = session.query(Node).filter(Node.latitude.isnot(None), Node.longitude.isnot(None)).all()
            if not nodes:
                return 0.0, 0.0

            lat_sum = mean(node.latitude for node in nodes)
            lon_sum = mean(node.longitude for node in nodes)

            logger.info(f'Calculated center coordinates: {lat_sum}, {lon_sum} for {len(nodes)} nodes')
            return lat_sum, lon_sum

    ### ADMIN NODES ###
    def is_admin_node(self, node_num: int) -> bool:
        with self.session() as session:
            admin_node = session.query(
                AdminNodes
            ).filter(
                AdminNodes.nodeNum == node_num,
                AdminNodes.enabled == True
            ).first()
            return admin_node is not None
        
    def get_active_admin_nodes(self) -> list[AdminNodes]:
        with self.session() as session:
            return session.query(AdminNodes).filter(AdminNodes.enabled == True).all()

    def disable_admins(self) -> None:
        with self.session() as session:
            session.query(AdminNodes).update({AdminNodes.enabled: False})
            session.commit()

    def insert_admin_node(self, node_num: int) -> None:
        with self.session() as session:
            stmt = Insert(AdminNodes).values(
                nodeNum=node_num,
                timestamp=int(time()),
                enabled=True
            ).on_conflict_do_update(
                index_elements=['nodeNum'],
                set_={
                    'enabled': True,
                    'timestamp': int(time())
                }
            )
            # on conflict, set to enabled
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

    def get_average_air_util(self, node_num: int, lookback_hours: int = 6) -> float:
        cutoff_time = int(time() - lookback_hours * 3600)
        with self.session() as session:
            avg_air_util = session.query(
                func.avg(TransmissionMetrics.airUtilTx)
            ).filter(
                TransmissionMetrics.rxTime >= cutoff_time,
                TransmissionMetrics.nodeNum == node_num
            ).scalar()
            return avg_air_util if avg_air_util is not None else 0.0

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
                raise ItemNotFound(f'Node {node_num} not found in db. Unable to update position.')
            node.lastHeard = last_heard
            node.latitude = latitude
            node.longitude = longitude
            node.altitude = altitude
            node.precisionBits = precision_bits
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
                timestamp=int(time())
            ))
            session.commit()

    def get_pending_notifications(self, to_id: int, max_attempts: int = 5, timestamp_cutoff: int = 0) -> list[OutgoingNotifications]:
        with self.session() as session:
            return session.query(
                OutgoingNotifications
            ).filter(
                OutgoingNotifications.toId == to_id,
                OutgoingNotifications.received == False,
                OutgoingNotifications.attempts < max_attempts,
                OutgoingNotifications.timestamp >= timestamp_cutoff
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
                logger.info(f'Marking notification {notif_tx_id} to node {notification.toId} as received.')
                notification.received = True
                session.add(notification)
                session.commit()

    ### ALERTS ###
    def get_node_alert_status(self, node_num: int) -> NodeAlerts:
        with self.session() as session:
            status = session.query(
                NodeAlarmStatus
            ).filter(
                NodeAlarmStatus.nodeNum == node_num
            ).first()

            if not status:
                return NodeAlerts(nodeNum=node_num)
            return NodeAlerts(**status.__dict__)
        
    def update_node_alert_status(self, update_payload: NodeAlerts) -> None:
        with self.session() as session:
            stmt = Insert(NodeAlarmStatus).values(
                nodeNum=update_payload.nodeNum,
                temperatureAlarm=update_payload.temperatureAlarm,
                humidityAlarm=update_payload.humidityAlarm,
                channelUsageAlarm=update_payload.channelUsageAlarm,
                batteryLevelAlarm=update_payload.batteryLevelAlarm,
                networkPathAlarm=update_payload.networkPathAlarm,
                errorRateAlarm=update_payload.networkPathAlarm
            ).on_conflict_do_update(
                index_elements=['nodeNum'],
                set_={
                    'temperatureAlarm': update_payload.temperatureAlarm,
                    'humidityAlarm': update_payload.humidityAlarm,
                    'channelUsageAlarm': update_payload.channelUsageAlarm,
                    'batteryLevelAlarm': update_payload.batteryLevelAlarm,
                    'networkPathAlarm': update_payload.networkPathAlarm,
                    'errorRateAlarm': update_payload.networkPathAlarm
                }
            )
            session.execute(stmt)
            session.commit()

    ### SUBSCRIPTIONS ###
    # def subscribe_to_category(self, node_num: int, category_id: int | None = None) -> None:
    #     '''
    #     Will raise IntegrityError if the categoryId is not valid.
    #     '''
    #     try:
    #         with self.session() as session:
    #             # check if an entry for user + category already exists
    #             user_subscription = session.query(Subscriptions).filter(
    #                 Subscriptions.nodeNum == node_num,
    #                 Subscriptions.categoryId == category_id
    #             ).first()

    #             if user_subscription:
    #                 user_subscription.timestamp = int(time())
    #                 user_subscription.isSubscribed = True
    #                 session.add(user_subscription)

    #             else:
    #                 stmt = Insert(Subscriptions).values(
    #                     nodeNum=node_num,
    #                     categoryId=category_id,
    #                     isSubscribed=True,
    #                     timestamp=int(time())
    #                 )
    #                 session.execute(stmt)

    #             session.commit()

    #     except IntegrityError:
    #         raise InvalidCategory(f'Category {category_id} does not exist.')
        
    # def subscribe_to_all(self, node_num: int) -> None:
    #     with self.session() as session:
    #         categories = session.query(BulletinBoardCategory).all()
    #         for category in categories:
    #             self.subscribe_to_category(node_num=node_num, category_id=category.id)
    #         session.commit()

    # def unsubscribe_from_category(self, node_num: int, category_id: int | None = None) -> None:
    #     with self.session() as session:
    #         subscription = session.query(Subscriptions).filter(
    #             Subscriptions.nodeNum == node_num,
    #             Subscriptions.categoryId == category_id
    #         ).first()
    #         if subscription:
    #             session.delete(subscription)
    #             session.commit()
    #         else:
    #             logger.warning(f'No subscription found for node {node_num} in category {category_id}.')

    # def unsubscribe_all(self, node_num: int) -> None:
    #     with self.session() as session:
    #         subscriptions = session.query(Subscriptions).filter(Subscriptions.nodeNum == node_num).all()
    #         for subscription in subscriptions:
    #             subscription.isSubscribed = False
    #             session.add(subscription)
    #         session.commit()

    # def list_subscribers(self, category_id: int) -> list[int]:
    #     # returns a list of node numbers that are subscribed to the given category
    #     with self.session() as session:
    #         subscribers = session.query(Subscriptions.nodeNum).filter(
    #             Subscriptions.categoryId == category_id,
    #             Subscriptions.isSubscribed == True
    #         ).all()
    #         return [subscriber[0] for subscriber in subscribers]

    # def list_user_subscriptions(self, node_num: int) -> list[tuple[int, str]]:
    #     with self.session() as session:
    #         subscriptions = session.query(
    #             Subscriptions.categoryId, BulletinBoardCategory.name
    #         ).join(
    #             BulletinBoardCategory, Subscriptions.categoryId == BulletinBoardCategory.id
    #         ).filter(
    #             Subscriptions.nodeNum == node_num,
    #             Subscriptions.isSubscribed == True
    #         ).order_by(
    #             Subscriptions.timestamp.desc()
    #         ).all()
    #         return subscriptions
        
    ### TRACEROUTES ###
    def insert_received_traceroute(
            self,
            tracerouteId: int,
            fromId: str,
            toId: str,
            rxTime: int,
            traceroute_dict: dict,
            snr_avg: float,
            direct_connection: bool) -> None:
        with self.session() as session:
            stmt = Insert(Traceroute).values(
                tracerouteId=tracerouteId,
                rxTime=rxTime,
                fromId=fromId,
                toId=toId,
                tracerouteDetails=traceroute_dict,
                snrAvg=snr_avg,
                directConnection=direct_connection,
            ).on_conflict_do_update(
                # we only have a duplicate id if we initiated the traceroute
                # if so, we can ignore fromId and toId since we already know that from before
                index_elements=['tracerouteId'],
                set_={
                    'rxTime': rxTime,
                    'tracerouteDetails': traceroute_dict,
                    'snr_avg': snr_avg,
                    'direct_connection': direct_connection
                }
            )
            session.execute(stmt)
            session.commit()

    def insert_traceroute_attempt(self, source_node: int, traceroute_id: int, toId: int) -> None:
        with self.session() as session:
            session.add(
                Traceroute(
                    tracerouteId=traceroute_id,
                    txTime=int(time()),
                    fromId=source_node,
                    toId=toId,
                )
            )
            session.commit()

    def retrieve_traceroute_results(self) -> list[Traceroute]:
        with self.session() as session:
            return session.query(
                Traceroute
            ).filter(
                Traceroute.tracerouteDetails.isnot(None)
            ).order_by(
                Traceroute.rxTime.desc()
            ).all()

    def select_traceroute_target(self, fromId: int, maxHops: int = 5) -> Node:
        '''
        Returns 1 node (if any) nodes where role == router | router_late,
        is less than 6 hops away,
        is NOT the current node,
        was last heard less than 1 week ago
        and has not had a traceroute attempt (txTime) sent to it in the past 3 hours.
        '''
        with self.session() as session:
            three_hours_ago = int(time() - timedelta(hours=3).total_seconds())
            one_week_ago = int(time() - timedelta(days=7).total_seconds())
            return session.query(
                Node
            ).filter(
                (Node.nodeRole == NodeRoles.ROUTER.value) | (Node.nodeRole == NodeRoles.ROUTER_LATE.value) | (Node.isFavorite == True),
                Node.hopsAway <= maxHops,
                Node.nodeNum != fromId,
                Node.lastHeard >= one_week_ago,
                ~Node.nodeNum.in_(
                    session.query(Traceroute.toId).filter(
                        Traceroute.txTime > three_hours_ago
                    )
                )
            ).order_by(
                Node.lastHeard.desc()
            ).first()

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
