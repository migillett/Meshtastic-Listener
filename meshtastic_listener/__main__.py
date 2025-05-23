import time
import sys
from os import environ, path, mkdir
from datetime import timedelta, datetime
from typing import Callable
from statistics import mean
import logging
import json
import signal

from meshtastic_listener.listener_db.listener_db import ListenerDb, ItemNotFound
from meshtastic_listener.commands.cmd_handler import CommandHandler, UnknownCommandError
from meshtastic_listener.data_structures import (
    MessageReceived, NodeBase, WaypointPayload,
    DevicePayload, TransmissionPayload, EnvironmentPayload
)
from meshtastic_listener.utils import calculate_distance, coords_int_to_float, load_node_env_var

from pubsub import pub
from meshtastic.tcp_interface import TCPInterface
from meshtastic.serial_interface import SerialInterface
from meshtastic.protobuf.portnums_pb2 import PortNum
from meshtastic.mesh_interface import MeshInterface
import toml


# the `/data` directory is for storing logs and .db files
abs_path = path.dirname(path.abspath(__file__))
logs_dir = path.join(abs_path, '..', 'logs')
if not path.exists(logs_dir):
    mkdir(logs_dir)

enable_debug: bool = environ.get('ENABLE_DEBUG', 'false').lower() == 'true'

logging.Formatter.converter = time.localtime

logging.basicConfig(
    level=logging.DEBUG if enable_debug else logging.INFO,
    format='%(asctime)s - %(levelname)s : %(message)s',
    handlers=[
        logging.FileHandler(path.join(logs_dir, 'listener.log')),
        logging.StreamHandler(sys.stdout)
    ],
    datefmt='%Y-%m-%d %H:%M:%S',
)


class EnvironmentError(Exception):
    pass


class MeshtasticListener:
    def __init__(
            self,
            interface: TCPInterface | SerialInterface,
            db_object: ListenerDb,
            cmd_handler: CommandHandler,
            update_interval: int = 15,
            admin_nodes: list[int] | None = None,
        ) -> None:

        version = toml.load('pyproject.toml')['tool']['poetry']['version']
        logging.info(f"====== Initializing Meshtastic Listener v{version} ======")
        
        self.interface = interface
        self.db = db_object
        self.cmd_handler = cmd_handler
        self.char_limit = 200

        self.local_node_id = self.interface.localNode.nodeNum

        self.max_channel_utilization = 35.0
        self.channel_usage_statistics: list[float] = []

        self.node_refresh_ts: float = time.time() - timedelta(hours=1).total_seconds()
        self.traceroute_ts: float = time.time() - timedelta(hours=1).total_seconds()
        self.update_interval = timedelta(minutes=update_interval)
        logging.info(f'Update interval set to every {update_interval} minutes')

        # where to send critical service notification messages
        if admin_nodes is not None:
            for node in admin_nodes:
                if not isinstance(node, int):
                    raise EnvironmentError(f"Invalid admin node ID: {node}. Must be an integer.")
                self.db.insert_admin_node(node)
            logging.info(f"Admin nodes set to: {admin_nodes}")
        else:
            logging.info("No admin nodes set. Some features will be disabled.")

        self.notification_ts = time.time()

        # logging device connection and db initialization
        logging.info(f'Connected to {self.interface.__class__.__name__} device: {self.interface.getShortName()}')
        logging.info(f'CommandHandler initialized with prefix: {self.cmd_handler.prefix}')

        self.__load_local_nodes__(force=True)

    def __human_readable_ts__(self, rxTime: int | None = None) -> str:
        if rxTime is None:
            return datetime.now().strftime("%m/%d %I:%M %p")
        else:
            return datetime.fromtimestamp(rxTime).strftime("%m/%d %I:%M %p")
    
    def __get_channel_utilization__(self) -> float:
        device_metrics = self.interface.getMyNodeInfo()
        if device_metrics is not None:
            current_utilization = float(device_metrics.get('deviceMetrics', {}).get('channelUtilization', 0.0))
            logging.info(f'Current channel utilization: {current_utilization}')
            return current_utilization
        else:
            logging.error('Unable to get device metrics from node')
            return 0.0

    def __notify_admins__(self, message: str) -> None:
        admin_nodes = self.db.get_active_admin_nodes()
        if admin_nodes is not None and len(admin_nodes) > 0:
            for admin_node in admin_nodes:
                self.db.insert_notification(
                    to_id=admin_node.nodeNum,
                    message=message
                )
            logging.info(f"Queued notification to {len(admin_nodes)} admin nodes: {message}")

    def __load_local_nodes__(self, force: bool = False) -> None:
        now = time.time()
        if (now - self.node_refresh_ts > self.update_interval.total_seconds() or force):
            if self.interface.nodes is None:
                logging.error(f'Interface reports no Nodes. Unable to load local nodes to DB.')
            else:
                nodes = [NodeBase(**node) for node in self.interface.nodes.values()]
                self.db.insert_nodes(nodes)
            self.node_refresh_ts = now

    def __check_channel_usage__(self, n_cycles: int = 5) -> None:
        if len(self.channel_usage_statistics) > n_cycles:
            mean_usage = round(mean(self.channel_usage_statistics), 2)
            if mean_usage > self.max_channel_utilization:
                logging.info(f'High channel usage reported for past {n_cycles} cycles. Sending notification to admins...')
                self.__notify_admins__(f'{self.__human_readable_ts__()}\nHigh channel usage for the past {n_cycles} cycles:\n{mean_usage}%')
            self.channel_usage_statistics = []

    def __send_messages__(self, text: str, destinationId: int) -> None:
        # splits the input text into chunks of char_limit length
        # 233 bytes is set by the meshtastic constants in mesh_pb.pyi
        # round down to 200 to account for the message header and pagination footer
        messages = [text[i:i + self.char_limit] for i in range(0, len(text), self.char_limit)]
        logging.debug(f'Transmitting response message in {len(messages)} part(s)')
        for i, message in enumerate(messages):
            if len(messages) > 1:
                message += f'\n({i + 1}/{len(messages)})'
            self.interface.sendText(
                text=message,
                destinationId=destinationId,
                channelIndex=0
            )
            
    def __print_packet_received__(self, logger: Callable, message: dict) -> None:
        node_num = message.get('from', 'UNKNOWN')
        if int(node_num) == int(self.local_node_id):
            return
        
        packet = message.get('decoded', {})

        snr = message.get('rxSnr', "N/A")
        rx_rssi = message.get('rxRssi', "N/A")
        msg_type = packet.get('portnum', 'UNKNOWN')

        shortname = self.db.get_shortname(node_num)
        log_insert = f"node {node_num}" if str(shortname) == str(node_num) else f"{shortname} ({node_num})"

        logger(f"Received {msg_type} payload from {log_insert} ({rx_rssi} dB rxRssi, {snr} rxSNR): {json.dumps(packet)}")
    
    def __handle_text_message__(self, packet: dict) -> None:
        self.__print_packet_received__(logging.info, packet)

        response = None
        if self.cmd_handler is not None:
            payload = MessageReceived(**packet)
            if payload.decoded.text is None:
                logging.warning(f'Message received has no text payload: {payload.model_dump()}')
                return None
            
            try:
                response = self.cmd_handler.handle_command(context=payload)
            
            except UnknownCommandError as e:
                self.__send_messages__(text=str(e), destinationId=payload.fromId)

            if isinstance(response, str):
                logging.info(f'Replying to {payload.fromId}: {response}')
                self.__send_messages__(text=response, destinationId=payload.fromId)

            elif isinstance(response, list):
                logging.info(f'Sending waypoint to {payload.fromId}: {response}')
                expiration_ts = int(time.time() + timedelta(days=7).total_seconds())
                for waypoint in response:
                    self.interface.sendWaypoint(
                        name=waypoint.name,
                        expire=expiration_ts,
                        description=waypoint.description or '',
                        latitude=coords_int_to_float(waypoint.latitudeI),
                        longitude=coords_int_to_float(waypoint.longitudeI),
                        destinationId=payload.fromId,
                        wantAck=False,
                        wantResponse=False
                    )
                
                n_waypoints = len(response)
                waypoint_insert = f"waypoint" if n_waypoints == 1 else "waypoints"
                logging.info(f'Sending {n_waypoints} {waypoint_insert} to {payload.fromId}')
                waypoint_msg = f'Sent {n_waypoints} {waypoint_insert} to your map:'
                for i, waypoint in enumerate(response):
                    waypoint_msg += f'\n {i+1}. {waypoint.name}'

                self.__send_messages__(
                    text=waypoint_msg,
                    destinationId=payload.fromId
                )

        # if someone sends a DM to the node that ISN'T a command, forward it to the admin nodes
        if (
            response is None and
            int(payload.toId) == int(self.local_node_id) and
            not self.db.is_admin_node(payload.fromId)
        ):
            self.__notify_admins__(
                message=f"rxTime: {self.__human_readable_ts__(payload.rxTime)}\nFWD from {self.db.get_shortname(payload.fromId)}:\n{payload.decoded.text}",
            )
           
    def __handle_telemetry__(self, packet: dict) -> None:
        telemetry = packet.get('decoded', {}).get('telemetry', {})

        self.__print_packet_received__(logging.debug, packet)

        if 'deviceMetrics' in telemetry:
            metrics = DevicePayload(**telemetry['deviceMetrics'])
            self.db.insert_device_metrics(
                packet['from'],
                packet.get('rxTime', int(time.time())),
                metrics
            )
        elif 'localStats' in telemetry:
            metrics = TransmissionPayload(**telemetry['localStats'])
            self.db.insert_transmission_metrics(
                packet['from'],
                packet.get('rxTime', int(time.time())),
                metrics
            )
        elif 'environmentMetrics' in telemetry:
            metrics = EnvironmentPayload(**telemetry['environmentMetrics'])
            self.db.insert_environment_metrics(
                packet['from'],
                packet.get('rxTime', int(time.time())),
                metrics
            )

        elif 'powerMetrics' in telemetry:
            # we don't care about power metrics
            pass

        else:
            logging.error(f"Unknown telemetry type: {telemetry}")

    def __handle_traceroute__(self, packet: dict) -> None:
        traceroute_details = packet.get('decoded', {}).get('traceroute', {})
        
        self.__print_packet_received__(logging.info, packet)

        direct_connection = 'route' not in traceroute_details
        snr_values = traceroute_details.get('snrTowards', []) + traceroute_details.get('snrBack', [])
        snr_avg = sum(snr_values) / len(snr_values) if snr_values else 0
        n_forward_hops = len(traceroute_details.get('route', []))

        self.db.insert_traceroute(
            fromId=packet['from'],
            toId=packet['to'],
            rxTime=packet['rxTime'],
            traceroute_dict=traceroute_details,
            snr_avg=snr_avg,
            direct_connection=direct_connection,
        )

        self.__notify_admins__(
            message=f"rxTime: {self.__human_readable_ts__(packet.get('rxTime', 0))}\nTraceroute from {self.db.get_shortname(packet['from'])}\nSNR: {round(snr_avg, 2)} dB\nHOPS: {n_forward_hops}\nDIRECT CONNECT: {direct_connection}"
        )

    def __handle_position__(self, packet: dict) -> None:
        position = packet.get('decoded', {}).get('position', {})
        self.__print_packet_received__(logging.debug, packet)

        node_details = self.interface.getMyNodeInfo()
        if node_details is None:
            logging.error('Mesh interface reports no local node. Unable to calculate position')
            return None

        node = NodeBase(**node_details)
        incoming_lat, incoming_lon = position.get('latitude'), position.get('longitude')
        distance: float | None = None
        
        if node.position.latitude is None or node.position.longitude is None:
            logging.error('Host node configuration does not include latitude and longitude. Unable to calculate distance.')
        elif incoming_lat is None and incoming_lon is None:
            logging.error('Unable to calculate distance, incoming node position does not contain latitude or longitude.')
        else:
            distance = calculate_distance(
                node.position.latitude,
                node.position.longitude,
                incoming_lat,
                incoming_lon
            )

        try:
            self.db.upsert_position(
                node_num=packet['from'],
                last_heard=position.get('time', int(time.time())),
                latitude=incoming_lat,
                longitude=incoming_lon,
                altitude=position.get('altitude'),
                distance=distance,
                precision_bits=position.get('precisionBits')
            )
            logging.debug(f'Updated position for node {packet["from"]}: {self.db.get_node(packet["from"])}')
        except ItemNotFound as e:
            logging.warning(e)

    def __traceroute_upstream__(self, max_hops: int = 5) -> None:
        '''
        runs a traceroute to nearby infrastructure nodes on a cron job
        '''
        now = time.time()
        # send traceroutes to nearby routers every n minutes
        if now - self.traceroute_ts > self.update_interval.total_seconds():
            usage = self.__get_channel_utilization__()
            if usage > self.max_channel_utilization:
                logging.warning(f'Channel utilization is greater than {self.max_channel_utilization}. Waiting for 15 minutes before sending the next traceroute.')
                self.traceroute_ts = now + timedelta(minutes=15).total_seconds()
                self.channel_usage_statistics.append(usage)
                return None
            
            target = self.db.select_traceroute_target(
                fromId=self.local_node_id,
                maxHops=max_hops
            )
            if not target:
                logging.info("No valid infrastructure nodes found in DB. Delaying next infrastructure traceroute request for 1 hour.")
                self.traceroute_ts = now + timedelta(hours=1).total_seconds()
                return None
            else:
                try:
                    logging.info(f"Sending traceroute to node: {target.nodeNum} ({target.longName})")
                    self.db.insert_traceroute_attempt(toId=target.nodeNum)
                    self.interface.sendTraceRoute(dest=target.nodeNum, hopLimit=max_hops)
                except MeshInterface.MeshInterfaceError as e:
                    logging.error(f"Failed to send traceroute to {target.nodeNum}: {e}")
            self.traceroute_ts = now

    def __handle_neighbor_update__(self, packet: dict) -> None:
        neighbor_info = packet.get('decoded', {}).get('neighborinfo', {})
        self.__print_packet_received__(logging.info, packet)
        for neighbor in neighbor_info.get('neighbors', []):
            if not neighbor.get('snr') or not neighbor.get('nodeId'):
                logging.error(f'Neighbor information is missing essential SNR and/or nodeID values: {neighbor}')
            else:
                self.db.insert_neighbor(
                    source_node_id=int(packet['from']),
                    neighbor_id=int(neighbor['nodeId']),
                    snr=float(neighbor['snr']),
                    rx_time=int(time.time())
                )

    def __handle_new_node__(self, node_num: int) -> None:
        if not self.db.get_node(node_num):
            self.__load_local_nodes__(force=True)

    def __handle_waypoint__(self, packet: dict) -> None:
        sender = int(packet.get('from', 0))
        if self.db.is_admin_node(sender):
            self.__print_packet_received__(logging.info, packet)
            waypoint_data = packet.get('decoded', {}).get('waypoint', {})
            waypoint = WaypointPayload(**waypoint_data)
            self.db.insert_waypoint(waypoint)
            logging.info(f"Received waypoint from admin node {sender}: {waypoint}")
        else:
            logging.info(f'Waypoint packet received from non-admin node: {self.db.get_shortname(sender)}. Ignoring.')

    def __trigger_notifications__(self, node_num: int) -> None:
        pending_notifications = self.db.get_pending_notifications(to_id=node_num)
        if len(pending_notifications) > 0 and self.notification_ts < time.time():     
            logging.info(f"Sending {len(pending_notifications)} notifications to node: {node_num}")
            for notif in pending_notifications:
                message_metadata = self.interface.sendText(
                    text=notif.message,
                    destinationId=node_num,
                    wantAck=True
                )

                # log the request_id for the notification so we can track if it was received
                # whenever we receive an ROUTER_APP packet from the notify_node
                # we check for the request_id in the notifications table
                try:
                    self.db.increment_notification_attempts(
                        notification_id=notif.id,
                        notif_tx_id=int(message_metadata.id)
                    )
                except ItemNotFound as e:
                    logging.warning(e)

            self.notification_ts = time.time() + timedelta(seconds=30).total_seconds()

    def __check_notification_received__(self, packet: dict) -> None:
        request_id = packet.get('decoded', {}).get('requestId')
        if request_id is None:
            logging.debug(f"Received ROUTER_APP packet with no valid requestId. Ignoring.")
            return
        self.db.mark_notification_received(notif_tx_id=request_id)

    def __sanitize_packet__(self, packet: dict) -> dict:
        response = {}
        for key in packet:
            if isinstance(packet[key], bytes) or key == 'raw':
                logging.debug(f'Dropping raw bytes from packet: {key}:{packet[key]}')
            elif isinstance(packet[key], dict):
                response[key] = self.__sanitize_packet__(packet[key])
            else:
                response[key] = packet[key]
        return response
 
    def __on_receive__(self, packet: dict, interface: MeshInterface | None = None) -> None:
        try:
            if 'encrypted' in packet:
                logging.debug(f"Received encrypted packet from {packet.get('from', 'UNKNOWN')}. Ignoring.")
                return
            
            packet = self.__sanitize_packet__(packet)
            
            self.__handle_new_node__(packet['from'])
            portnum = packet.get('decoded', {}).get('portnum', None)

            # checks if the sender has a pending notification
            self.__trigger_notifications__(packet['from'])
            
            try:
                self.db.insert_message_history(
                    rx_time=int(time.time()),
                    from_id=packet['from'],
                    to_id=packet['to'],
                    portnum=portnum,
                    packet_raw=packet
                )
            except KeyError as e:
                logging.exception(f"{e}: Failed to insert message history for packet: {packet}")

            match getattr(PortNum, portnum, None):
                case PortNum.TEXT_MESSAGE_APP:
                    self.__handle_text_message__(packet)
                case PortNum.TELEMETRY_APP:
                    self.__handle_telemetry__(packet)
                case PortNum.NODEINFO_APP:
                    logging.debug(f'NODEINFO_APP packet received from {packet["from"]}. Refreshing local nodes...')
                    self.__load_local_nodes__(force=True)
                case PortNum.TRACEROUTE_APP:
                    self.__handle_traceroute__(packet)
                case PortNum.POSITION_APP:
                    self.__handle_position__(packet)
                case PortNum.NEIGHBORINFO_APP:
                    self.__handle_neighbor_update__(packet)
                case PortNum.WAYPOINT_APP:
                    self.__handle_waypoint__(packet)
                case PortNum.ROUTING_APP:
                    # this is how we confirm that a message was received by the notify_node
                    self.__check_notification_received__(packet)
                case PortNum.STORE_FORWARD_APP:
                    pass
                # TODO - define and handle a custom portnum for DB Syncing
                case PortNum.ADMIN_APP:
                    pass
                case _:
                    logging.info(f"Received unhandled {portnum} packet: {packet}\n")
        except UnicodeDecodeError:
            logging.error(f"Message decoding failed due to UnicodeDecodeError: {packet}")

    def __exit__(self, signum, frame) -> None:
        logging.info("Received shutdown signal. Exiting gracefully...")
        self.interface.close()
        logging.info("====== MeshtasticListener Exiting ======")
        exit(0)
    
    def run(self):
        signal.signal(signal.SIGTERM, self.__exit__)

        pub.subscribe(self.__on_receive__, "meshtastic.receive")
        logging.info("Subscribed to meshtastic.receive")
        
        while True:
            try:
                sys.stdout.flush()
                self.__load_local_nodes__()
                self.__traceroute_upstream__()
                self.__check_channel_usage__()
                time.sleep(1)
            except Exception as e:
                logging.exception(f"Encountered fatal error in main loop: {e}")
                raise e
            except KeyboardInterrupt:
                self.__exit__(None, None)

if __name__ == "__main__":
    device_ip = environ.get("DEVICE_IP")
    try:
        interface = TCPInterface(hostname=device_ip) if device_ip is not None else SerialInterface()
    except ConnectionRefusedError:
        logging.warning(f"Connection to {device_ip} refused. Exiting...")
        exit(1)

    db_object = ListenerDb(
        hostname=environ.get("POSTGRES_HOSTNAME", "listener_db"),
        username=environ.get("POSTGRES_USER", 'postgres'),
        password=environ.get("POSTGRES_PASSWORD", 'password'),
        db_name=environ.get("POSTGRES_DATABASE", 'listener_db'),
        default_categories=[
            c.title().strip() for c in environ.get("DEFAULT_CATEGORIES", 'Annoucements,General,Events').split(',')
        ],
    )

    cmd_handler = CommandHandler(
        cmd_db=db_object,
        server_node_id=int(interface.localNode.nodeNum),
        prefix=environ.get("CMD_PREFIX", '!'),
        bbs_lookback=int(environ.get("BBS_DAYS", 7))
    )

    listener = MeshtasticListener(
        interface=interface,
        db_object=db_object,
        cmd_handler=cmd_handler,
        update_interval=int(environ.get("UPDATE_INTERVAL", 15)),
        admin_nodes=load_node_env_var("ADMIN_NODE_IDS")
    )
    
    listener.run()
