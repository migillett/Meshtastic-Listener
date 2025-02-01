import time
import sys
from os import environ, path, mkdir
from datetime import timedelta
import logging
import signal

from meshtastic_listener.db_utils import ListenerDb
from meshtastic_listener.cmd_handler import CommandHandler
from meshtastic_listener.data_structures import (
    MessageReceived, NodeBase,
    DeviceMetrics, TransmissionMetrics, EnvironmentMetrics
)

from pubsub import pub
from meshtastic.tcp_interface import TCPInterface
from meshtastic.serial_interface import SerialInterface
from meshtastic.mesh_interface import MeshInterface
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
            debug: bool = False,
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

        # logging device connection and db initialization
        logging.info(f'Connected to {self.interface.__class__.__name__} device: {self.interface.getShortName()}')
        logging.info(f'ListenerDb initialized with db_path: {self.db.db_path}')
        logging.info(f'CommandHandler initialized with prefix: {self.cmd_handler.prefix}')
        if self.cmd_handler.admin_node_id is not None:
            logging.info(f'Admin node ID set to: {self.cmd_handler.admin_node_id}')
        else:
            logging.info('Admin node ID not set. Admin commands will not be available.')

        self.__load_local_nodes__(force=True)


    def __load_local_nodes__(self, force: bool = False) -> None:
        now = time.time()
        if now - self.node_refresh_ts > self.node_refresh_interval.total_seconds() or force:
            nodes = [NodeBase(**node) for node in self.interface.nodes.values()]
            self.db.insert_nodes(nodes)
            self.node_refresh_ts = now

    def __reconnect__(self) -> None:
        logging.error("Connection lost with node. Attempting to reconnect...")
        self.interface.close()
        self.interface.connect()

    def __reply__(self, text: str, destinationId: int) -> None:
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
            
    def __print_packet_received__(self, msg_type: str, node_num: int, packet: dict) -> None:
        if 'raw' in packet:
            packet.pop('raw')

        shortname = self.db.get_shortname(node_num)
        if str(shortname) == str(node_num):
            log_insert = f"node {node_num}"
        else:
            log_insert = f"{shortname} ({node_num})"

        msg = f"Received {msg_type} payload from {log_insert}: {packet}"
        if int(node_num) == int(self.interface.localNode.nodeNum):
            logging.debug(msg)
        else:
            logging.info(msg)
    
    def __handle_text_message__(self, packet: dict) -> None:
        # remap keys to match the MessageReceived model
        packet['fromId'] = packet['from']
        packet['toId'] = packet['to']
        sender = self.db.get_shortname(packet['fromId'])
        payload = MessageReceived(fromName=sender, **packet)

        self.__print_packet_received__('text message', packet['from'], payload.decoded.model_dump())

        if self.cmd_handler is not None:
            response = self.cmd_handler.handle_command(context=payload)
            if response is not None:
                logging.info(f'Replying to {payload.fromId}: {response}')
                self.__reply__(text=response, destinationId=payload.fromId)
        else:
            logging.error("Command Handler not initialized. Cannot reply to message.")

    def __handle_telemetry__(self, packet: dict) -> None:
        telemetry = packet.get('decoded', {}).get('telemetry', {})

        self.__print_packet_received__('telemetry', packet['from'], telemetry)

        if 'deviceMetrics' in telemetry:
            metrics = DeviceMetrics(**telemetry['deviceMetrics'])
            self.db.insert_device_metrics(packet['from'], metrics)
        elif 'localStats' in telemetry:
            metrics = TransmissionMetrics(**telemetry['localStats'])
            self.db.insert_transmission_metrics(packet['from'], metrics)
        elif 'environmentMetrics' in telemetry:
            metrics = EnvironmentMetrics(**telemetry['environmentMetrics'])
            self.db.insert_environment_metrics(packet['from'], metrics)
        else:
            logging.error(f"Unknown telemetry type: {telemetry}")
            return

    def __handle_traceroute__(self, packet: dict) -> None:
        traceroute_details = packet.get('decoded', {}).get('traceroute', {})
        traceroute_details.pop('raw', None)
        
        self.__print_packet_received__('traceroute', packet['from'], traceroute_details)

        direct_connection = 'route' not in traceroute_details or 'routeBack' not in traceroute_details
        snr_values = traceroute_details.get('snrTowards', []) + traceroute_details.get('snrBack', [])
        snr_avg = sum(snr_values) / len(snr_values) if snr_values else 0

        self.db.insert_traceroute(
            fromId=packet['from'],
            toId=packet['to'],
            traceroute_dict=traceroute_details,
            snr_avg=snr_avg,
            direct_connection=direct_connection,
        )

    def __handle_position__(self, packet: dict) -> None:
        position = packet.get('decoded', {}).get('position', {})
        self.__print_packet_received__('position', packet['from'], position)
        self.db.upsert_position(
            node_num=packet['from'],
            last_heard=position.get('time', int(time.time())),
            latitude=position.get('latitude'),
            longitude=position.get('longitude'),
            altitude=position.get('altitude'),
            precision_bits=position.get('precisionBits')
        )

    def __handle_new_node__(self, node_num: int) -> None:
        if not self.db.get_node(node_num):
            if self.welcome_message is not None:
                logging.info(f"Sending welcome message to {node_num}")
                self.__reply__(
                    text=self.welcome_message,
                    destinationId=node_num)
            self.__load_local_nodes__(force=True)

    def __on_receive__(self, packet: dict, interface: MeshInterface | None = None) -> None:
        try:
            self.__handle_new_node__(packet['from'])
            try:
                self.db.insert_message_history(packet)
            except KeyError as e:
                logging.exception(f"{e}: Failed to insert message history for packet: {packet}")

            portnum = packet.get('decoded', {}).get('portnum', None)
            match portnum:
                case 'TEXT_MESSAGE_APP':
                    self.__handle_text_message__(packet)
                case "TELEMETRY_APP":
                    self.__handle_telemetry__(packet)
                case "NODEINFO_APP":
                    logging.info('NODEINFO_APP packet received. Refreshing local nodes...')
                    self.__load_local_nodes__(force=True)
                case "TRACEROUTE_APP":
                    self.__handle_traceroute__(packet)
                case "POSITION_APP":
                    self.__handle_position__(packet)
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
        pub.subscribe(self.__reconnect__, "meshtastic.connection.lost")
        logging.info("Subscribed to meshtastic.receive")
        
        while True:
            try:
                sys.stdout.flush()
                self.__load_local_nodes__()
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
        prefix=environ.get("CMD_PREFIX", '!'),
        cmd_db=db_object,
        bbs_lookback=int(environ.get("BBS_DAYS", 7)),
        admin_node_id=environ.get("ADMIN_NODE_ID"),
        character_limit=char_limit
    )

    listener = MeshtasticListener(
        interface=interface,
        db_object=db_object,
        cmd_handler=cmd_handler,
        node_update_interval=int(environ.get("NODE_UPDATE_INTERVAL", 15)),
        response_char_limit=char_limit,
        welcome_message=environ.get("WELCOME_MESSAGE")
    )
    
    listener.run()