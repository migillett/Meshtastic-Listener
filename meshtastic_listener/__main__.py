import time
import sys
from os import environ, path, mkdir
from datetime import timedelta
import logging
import signal

from meshtastic_listener.db_utils import ListenerDb, ItemNotFound
from meshtastic_listener.cmd_handler import CommandHandler, UnauthorizedError
from meshtastic_listener.data_structures import (
    MessageReceived, NodeBase, WaypointPayload,
    DevicePayload, TransmissionPayload, EnvironmentPayload
)
from meshtastic_listener.position_utils import calculate_distance, coords_int_to_float

from pubsub import pub
from meshtastic.tcp_interface import TCPInterface
from meshtastic.serial_interface import SerialInterface
from meshtastic.mesh_interface import MeshInterface
from tenacity import retry, stop_after_attempt, wait_fixed
import toml


# the `/data` directory is for storing logs and .db files
abs_path = path.dirname(path.abspath(__file__))
data_dir = path.join(abs_path, '..', 'data')
if not path.exists(data_dir):
    mkdir(data_dir)

enable_debug: bool = environ.get('ENABLE_DEBUG', 'false').lower() == 'true'

logging.basicConfig(
    level=logging.DEBUG if enable_debug else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s: %(message)s',
    handlers=[
        logging.FileHandler(path.join(data_dir, 'listener.log')),
        logging.StreamHandler(sys.stdout)
    ],
    datefmt='%Y-%m-%d %H:%M:%S'
)


class EnvironmentError(Exception):
    pass


class MeshtasticListener:
    def __init__(
            self,
            interface: TCPInterface | SerialInterface,
            db_object: ListenerDb,
            cmd_handler: CommandHandler,
            node_update_interval: int = 15,
            response_char_limit: int = 200,
            welcome_message: str | None = None,
            traceroute_interval: int = 24,
            traceroute_node: str | None = None,
            notify_node: int | None = None
        ) -> None:

        version = toml.load('pyproject.toml')['tool']['poetry']['version']
        logging.info(f"====== Initializing MeshtasticListener v{version} ======")
        
        self.interface = interface
        self.db = db_object
        self.cmd_handler = cmd_handler
        self.char_limit = response_char_limit
        self.welcome_message = welcome_message

        self.node_refresh_ts: float = time.time()
        self.node_refresh_interval = timedelta(minutes=node_update_interval)

        self.traceroute_interval = timedelta(hours=traceroute_interval)
        self.traceroute_ts: float = time.time() - self.traceroute_interval.total_seconds()

        # node values can be integers or strings that start with "!"
        # all env vars are strings, so we need to check for both types
        self.traceroute_node = self.__check_node_id__(traceroute_node)

        # where to send notification messages
        self.notify_node: int | None = None
        if notify_node is not None:
            self.notify_node = int(notify_node)
        self.notification_ts = time.time()

        self.rx_rssi_stats = []

        # logging device connection and db initialization
        logging.info(f'Connected to {self.interface.__class__.__name__} device: {self.interface.getShortName()}')
        logging.info(f'ListenerDb initialized with db_path: {self.db.db_path}')
        logging.info(f'CommandHandler initialized with prefix: {self.cmd_handler.prefix}')
        if self.cmd_handler.admin_node_id is not None:
            logging.info(f'Admin node ID set to: {self.cmd_handler.admin_node_id}')
        else:
            logging.info('Admin node ID not set. Admin commands will not be available.')

        if self.traceroute_node is not None:
            logging.info(f'Traceroute node set to: {self.traceroute_node} with interval: {self.traceroute_interval}')

        self.__load_local_nodes__(force=True)

    def __check_node_id__(self, node_id: str | None) -> str | int | None:
        if node_id is not None:
            if not node_id.startswith('!'):
                return int(node_id)
        return node_id

    def __load_local_nodes__(self, force: bool = False) -> None:
        now = time.time()
        if now - self.node_refresh_ts > self.node_refresh_interval.total_seconds() or force:
            nodes = [NodeBase(**node) for node in self.interface.nodes.values()]
            self.db.insert_nodes(nodes)
            self.node_refresh_ts = now

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def __reconnect__(self, **kwargs) -> None:
        logging.error("Connection lost with node. Attempting to reconnect...")
        self.interface.close()
        self.interface.connect()

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
                channelIndex=0)
            
    def __print_packet_received__(self, msg_type: str, node_num: int, packet: dict, rx_rssi: float) -> None:
        if int(node_num) == int(self.interface.localNode.nodeNum):
            return
        if 'raw' in packet:
            packet.pop('raw')

        shortname = self.db.get_shortname(node_num)
        if str(shortname) == str(node_num):
            log_insert = f"node {node_num}"
        else:
            log_insert = f"{shortname} ({node_num})"

        logging.info(f"Received {msg_type} payload from {log_insert} ({rx_rssi} dB rxRssi): {packet}")
    
    def __handle_text_message__(self, packet: dict) -> None:
        self.__print_packet_received__('text message', packet['from'], packet.get('decoded', {}), packet.get('rxRssi', 0))

        if self.cmd_handler is not None:
            payload = MessageReceived(**packet)
            try:
                response = self.cmd_handler.handle_command(context=payload)
            except UnauthorizedError as e:
                logging.error(f'User unauthorized to execute command: {e}')
                if self.notify_node is not None:
                    self.db.insert_notification(
                        to_id=self.notify_node,
                        message=f"Unauthorized command execution attempt from {payload.fromId}: {e}")
                self.db.increment_failed_attempts(payload.fromId)
                return 'You are not authorized to run this command.'

            if type(response) is str:
                logging.info(f'Replying to {payload.fromId}: {response}')
                self.__send_messages__(text=response, destinationId=payload.fromId)

            elif type(response) is list:
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
                    
                logging.info(f'Sent {len(response)} waypoints to {payload.fromId}')
                self.__send_messages__(
                    text=f'Sent {len(response)} {"waypoints" if len(response) > 0 else "waypoint"} to your map',
                    destinationId=payload.fromId
                )

            elif response is None and self.notify_node is not None:
                # for those times when it's NOT a command, just forward the message to the admin node
                self.__forward_direct_messages__(packet)

        else:
            logging.error("Command Handler not initialized. Cannot reply to message.")

    def __handle_telemetry__(self, packet: dict) -> None:
        telemetry = packet.get('decoded', {}).get('telemetry', {})

        self.__print_packet_received__('telemetry', packet['from'], telemetry, packet.get('rxRssi', 0))

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
        else:
            logging.error(f"Unknown telemetry type: {telemetry}")
            return

    def __handle_traceroute__(self, packet: dict) -> None:
        traceroute_details = packet.get('decoded', {}).get('traceroute', {})
        traceroute_details.pop('raw', None)
        
        self.__print_packet_received__('traceroute', packet['from'], traceroute_details, packet.get('rxRssi', 0))

        direct_connection = 'route' not in traceroute_details
        snr_values = traceroute_details.get('snrTowards', []) + traceroute_details.get('snrBack', [])
        snr_avg = sum(snr_values) / len(snr_values) if snr_values else 0
        hops = len(snr_values)

        self.db.insert_traceroute(
            fromId=packet['from'],
            toId=packet['to'],
            rxTime=packet['rxTime'],
            traceroute_dict=traceroute_details,
            snr_avg=snr_avg,
            direct_connection=direct_connection,
        )

        if self.notify_node is not None:
            # add a slight delay to give time for the db to update
            self.notification_ts = time.time() + timedelta(seconds=30).total_seconds()
            from_shortname = self.db.get_shortname(packet['from'])
            self.db.insert_notification(
                to_id=self.notify_node,
                message=f"Received traceroute from {from_shortname}: SNR: {round(snr_avg, 2)} dB, HOPS: {hops}")
            logging.info(f'Queued traceroute notification delivery for node: {self.notify_node}')

    def __forward_direct_messages__(self, packet: dict) -> None:
        '''
        Forwards messages sent directly to the server node (assumed headless) to the notify/admin node
        '''
        message = packet.get('decoded', {}).get('text', None)
        if int(packet['to']) == int(self.interface.localNode.nodeNum) and message is not None:
            logging.info(f'Forwarding direct message from {packet["from"]} to admin node: {self.notify_node}')
            self.__send_messages__(text=f'FWD from {self.db.get_shortname(packet["to"])}: {message}', destinationId=self.notify_node)

    def __print_rxrssi_stats__(self, rx_rssi: int, average_n: int = 10) -> None:
        self.rx_rssi_stats.append(rx_rssi)
        if len(self.rx_rssi_stats) > average_n:
            logging.info(f'Average rxRssi for the past {average_n} packets: {round(sum(self.rx_rssi_stats) / len(self.rx_rssi_stats), 2)} dB')
            self.rx_rssi_stats = []

    def __handle_position__(self, packet: dict) -> None:
        position = packet.get('decoded', {}).get('position', {})
        self.__print_packet_received__('position', packet['from'], position, packet.get('rxRssi', 0))

        try:
            node_details = self.interface.getMyNodeInfo()
            node = NodeBase(**node_details)
            distance = calculate_distance(
                node.position.latitude,
                node.position.longitude,
                position.get('latitude'),
                position.get('longitude')
            )
        except Exception as e:
            logging.error(f"{e}: Unable to calculate distance from base node to {packet['from']}. Base node position not configured.")
            distance = None

        self.db.upsert_position(
            node_num=packet['from'],
            last_heard=position.get('time', int(time.time())),
            latitude=position.get('latitude'),
            longitude=position.get('longitude'),
            altitude=position.get('altitude'),
            distance=distance,
            precision_bits=position.get('precisionBits')
        )
        logging.debug(f'Updated position for node {packet["from"]}: {self.db.get_node(packet["from"])}')

    def __connect_upstream__(self) -> None:
        '''
        runs a traceroute every n hours to a specific infrastructure node that the user defines
        '''
        now = time.time()
        if now - self.traceroute_ts > self.traceroute_interval.total_seconds():
            if not self.traceroute_node:
                logging.info("Traceroute node was not defined. Skipping traceroute.")
            else:
                try:
                    logging.info(f"Attempting traceroute to node: {self.traceroute_node}")
                    self.interface.sendTraceRoute(self.traceroute_node, hopLimit=5)
                except MeshInterface.MeshInterfaceError as e:
                    logging.error(f"Failed to send traceroute to {self.traceroute_node}: {e}")
            self.traceroute_ts = now

    def __handle_neighbor_update__(self, packet: dict) -> None:
        neighbor_info = packet.get('decoded', {}).get('neighborinfo', {})
        self.__print_packet_received__('neighbor info', packet['from'], neighbor_info, packet.get('rxRssi', 0))
        for neighbor in neighbor_info.get('neighbors', []):
            self.db.insert_neighbor(
                source_node_id=packet['from'],
                neighbor_id=neighbor['nodeId'],
                snr=neighbor['snr'],
                rx_time=int(time.time())
            )

    def __handle_new_node__(self, node_num: int) -> None:
        if not self.db.get_node(node_num):
            if self.welcome_message is not None:
                logging.info(f"Sending welcome message to {node_num}")
                self.__send_messages__(
                    text=self.welcome_message,
                    destinationId=node_num)
            self.__load_local_nodes__(force=True)

    def __handle_waypoint__(self, packet: dict) -> None:
        sender = int(packet.get('from', 0))
        if sender == self.notify_node:
            self.__print_packet_received__('waypoint', sender, packet.get('decoded', {}), packet.get('rxRssi', 0))
            waypoint_data = packet.get('decoded', {}).get('waypoint', {})
            waypoint_data.pop('raw')
            waypoint = WaypointPayload(**waypoint_data)
            self.db.insert_waypoint(waypoint)
        else:
            logging.info(f'Waypoint packet received from {self.db.get_shortname(sender)}. Ignoring.')

    def __trigger_notifications_to_admin__(self) -> None:
        '''
        if an incoming packet has the same `from` node as the `notify_node`,
        get all of the pending notifications from the DB and send them to the admin node
        '''
        notifications = self.db.get_pending_notifications()
        if len(notifications) == 0:
            logging.debug("No notifications to send to admin node.")
            return
        
        logging.info(f"Sending {len(notifications)} notifications to admin node: {self.notify_node}")
        for notif in notifications:
            message_metadata = self.interface.sendText(
                text=notif.message,
                destinationId=self.notify_node,
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
    
    def __sender_is_notify_node__(self, node_id: int) -> bool:
        if self.notify_node is not None:
            return int(self.notify_node) == int(node_id)
        return False

    def __check_notification_received__(self, packet: dict) -> None:
        if self.__sender_is_notify_node__(packet['from']) and self.db.check_pending_notifications():
            decoded = packet.get('decoded', {})
            try:
                request_id = decoded['requestId'] # throws KeyError if not found
                self.db.mark_notification_received(notif_tx_id=request_id)
                logging.info(f"Notification message with id {request_id} confirmed by admin node: {packet['from']}")
            except KeyError:
                logging.warning(f"Received ROUTER_APP packet from {packet['from']} without a request_id: {decoded}")

    def __on_receive__(self, packet: dict, interface: MeshInterface | None = None) -> None:
        try:
            if 'encrypted' in packet:
                logging.debug(f"Received encrypted packet from {packet.get('from', 'UNKNOWN')}. Ignoring.")
                return
            
            if self.db.check_node_lockout(packet['from']):
                logging.info(f"Node {packet['from']} is locked out due to too many malicious requests. Ignoring packet.")
                return
            
            rx_rssi = packet.get('rxRssi')
            if rx_rssi is not None:
                self.__print_rxrssi_stats__(float(rx_rssi))
            
            self.__handle_new_node__(packet['from'])
            portnum = packet.get('decoded', {}).get('portnum', None)

            if self.__sender_is_notify_node__(packet['from']) and self.notification_ts < time.time():
                # don't spam notifications otherwise the return packet acknowledgement won't work
                logging.debug(f'Packet received from notify_node {self.notify_node}. Triggering notifications...')
                self.__trigger_notifications_to_admin__()
                self.notification_ts = time.time() + timedelta(minutes=5).total_seconds()
            
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

            match portnum:
                case 'TEXT_MESSAGE_APP':
                    self.__handle_text_message__(packet)
                case "TELEMETRY_APP":
                    self.__handle_telemetry__(packet)
                case "NODEINFO_APP":
                    logging.info(f'NODEINFO_APP packet received from {packet["from"]}. Refreshing local nodes...')
                    self.__load_local_nodes__(force=True)
                case "TRACEROUTE_APP":
                    self.__handle_traceroute__(packet)
                case "POSITION_APP":
                    self.__handle_position__(packet)
                case "NEIGHBORINFO_APP":
                    self.__handle_neighbor_update__(packet)
                case "WAYPOINT_APP":
                    self.__handle_waypoint__(packet)
                case "ROUTING_APP":
                    # this is how we confirm that a message was received by the notify_node
                    self.__check_notification_received__(packet)
                case "STORE_FORWARD_APP":
                    pass
                case _:
                    logging.info(f"Received unhandled {portnum} packet: {packet}\n")
        except UnicodeDecodeError:
            logging.error(f"Message decoding failed due to UnicodeDecodeError: {packet}")
    
    def run(self):
        def handle_shutdown_signal(signum, frame):
            logging.info(f"Received shutdown signal: {signum}. Exiting gracefully...")
            self.interface.close()
            logging.info("====== MeshtasticListener Exiting ======")
            exit(0)

        signal.signal(signal.SIGTERM, handle_shutdown_signal)

        pub.subscribe(self.__on_receive__, "meshtastic.receive")
        # TODO: disabling temporarly for now due to error:
        # pubsub.core.topicargspec.SenderUnknownMsgDataError:
            # Some optional args unknown in call to sendMessage('('meshtastic', 'connection', 'lost')', interface): interface
        # pub.subscribe(self.__reconnect__, "meshtastic.connection.lost")
        logging.info("Subscribed to meshtastic.receive")
        
        while True:
            try:
                sys.stdout.flush()
                self.__load_local_nodes__()
                self.__connect_upstream__()
                time.sleep(1)
            except Exception as e:
                logging.exception(f"Encountered fatal error in main loop: {e}")
                raise e

if __name__ == "__main__":
    device = environ.get("DEVICE_INTERFACE")
    try:
        # IP address
        if device and len(device.split('.')) == 4:
            interface = TCPInterface(hostname=device)
        # Serial port path
        else:
            interface = SerialInterface()
    except ConnectionRefusedError:
        logging.warning(f"Connection to {device} refused. Exiting...")
        exit(1)

    admin_node = environ.get("ADMIN_NODE_ID")
    if admin_node is not None:
        try:
            admin_node = int(admin_node)
        except ValueError:
            raise EnvironmentError("Invalid value for ADMIN_NODE_ID: must be an integer")

    # sanitizing the db_path
    db_path = environ.get("DB_NAME", ':memory:')
    if db_path != ':memory:':
        if not db_path.endswith('.db'):
            raise EnvironmentError("DB_NAME must be a .db file")
        if '/' in db_path or '\\' in db_path:
            raise EnvironmentError("DB_NAME must be a filename only")
        
    char_limit = int(environ.get("RESPONSE_CHAR_LIMIT", 200))

    db_object = ListenerDb(
        db_path=path.join(data_dir, db_path)
    )

    cmd_handler = CommandHandler(
        cmd_db=db_object,
        server_node_id=int(interface.localNode.nodeNum),
        prefix=environ.get("CMD_PREFIX", '!'),
        bbs_lookback=int(environ.get("BBS_DAYS", 7)),
        admin_node_id=admin_node,
        character_limit=char_limit
    )

    listener = MeshtasticListener(
        interface=interface,
        db_object=db_object,
        cmd_handler=cmd_handler,
        node_update_interval=int(environ.get("NODE_UPDATE_INTERVAL", 15)),
        response_char_limit=char_limit,
        welcome_message=environ.get("WELCOME_MESSAGE"),
        traceroute_interval=int(environ.get("TRACEROUTE_INTERVAL", 24)),
        traceroute_node=environ.get("TRACEROUTE_NODE"),
        notify_node=admin_node
    )
    
    listener.run()