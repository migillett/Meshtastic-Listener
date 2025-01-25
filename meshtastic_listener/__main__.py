import time
import sys
from os import environ, path, mkdir
from datetime import timedelta
import logging
import signal

from meshtastic_listener.db_utils import ListenerDb
from meshtastic_listener.cmd_handler import CommandHandler
from meshtastic_listener.data_structures import MessageReceived, NodeBase, DeviceMetrics

from pubsub import pub
from meshtastic.tcp_interface import TCPInterface
from meshtastic.serial_interface import SerialInterface
import toml


# the `/data` directory is for storing logs and .db files
abs_path = path.dirname(path.abspath(__file__))
data_dir = path.join(abs_path, '..', 'data')
if not path.exists(data_dir):
    mkdir(data_dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(path.join(data_dir, 'listener.log')),
        logging.StreamHandler(sys.stdout)]
)


class MeshtasticListener:
    def __init__(
            self,
            interface: TCPInterface | SerialInterface,
            db_object: ListenerDb,
            cmd_handler: CommandHandler | None,
            node_update_interval: int = 15,
            response_char_limit: int = 220,
            welcome_message: str | None = None,
        ) -> None:

        version = toml.load('pyproject.toml')['tool']['poetry']['version']
        logging.info(f"====== Initializing MeshtasticListener v{version} ======")
        
        self.interface = interface
        self.db = db_object
        self.cmd_handler = cmd_handler

        self.node_refresh_ts: float = time.time()
        self.node_refresh_interval = timedelta(minutes=node_update_interval)
        self.__load_local_nodes__(force=True)

        self.char_limit = response_char_limit
        self.welcome_message = welcome_message

    def __load_local_nodes__(self, force: bool = False) -> None:
        now = time.time()
        if now - self.node_refresh_ts > self.node_refresh_interval.total_seconds() or force:
            logging.info("Refreshing Node details")
            nodes = [NodeBase(**node) for node in self.interface.nodes.values()]
            self.db.insert_nodes(nodes)
            self.node_refresh_ts = now

    def __reply__(self, text: str, destinationId: int) -> None:
        # splits the input text into chunks of char_limit length
        # 233 bytes is set by the meshtastic constants in mesh_pb.pyi
        # round down to 200 to account for the message header and pagination footer
        messages = [text[i:i + self.char_limit] for i in range(0, len(text), self.char_limit)]
        logging.info(f'Transmitting response message in {len(messages)} part(s)')
        for i, message in enumerate(messages):
            if len(messages) > 1:
                message += f'\n({i + 1}/{len(messages)})'
            self.interface.sendText(
                text=message,
                destinationId=destinationId,
                channelIndex=0)
    
    def __handle_text_message__(self, packet: dict) -> None:
        # remap keys to match the MessageReceived model
        packet['fromId'] = packet['from']
        packet['toId'] = packet['to']
        sender = self.db.get_node_shortname(packet['fromId'])
        payload = MessageReceived(fromName=sender, **packet)

        logging.info(f"Message Received: {payload.fromName} - {payload.decoded.payload}")
        if self.cmd_handler is not None:
            response = self.cmd_handler.handle_command(context=payload)
            if response is not None:
                logging.info(f'Replying to {payload.fromId}: {response}')
                self.__reply__(text=response, destinationId=payload.fromId)
        else:
            logging.error("Command Handler not initialized. Cannot reply to message.")

    def __handle_telemetry__(self, packet: dict) -> None:
        node_num = packet.get('from', None)
        if node_num is None:
            logging.error(f"Telemetry packet missing 'from' field: {packet}")
            return

        telemetry = packet.get('decoded', {}).get('telemetry', {})
        metrics = telemetry.get('deviceMetrics', {})
        local_stats = telemetry.get('localStats', {})

        combined_metrics = DeviceMetrics(**metrics, **local_stats)
        logging.info(f"Telemetry Received from {node_num}: {combined_metrics.model_dump_json()}")
        self.db.insert_metrics(node_num, combined_metrics)

    def __handle_new_node__(self, node_num: int) -> None:
        if not self.db.check_node_exists(node_num):
            logging.info(f"New Node detected: {node_num}. Attempting traceroute...")
            self.interface.sendTraceRoute(destinationId=node_num, hopLimit=5, channelIndex=0)
            if self.welcome_message is not None:
                logging.info(f"Sending welcome message to {node_num}")
                self.__reply__(
                    text=self.welcome_message,
                    destinationId=node_num)
            self.__load_local_nodes__(force=True)

    def __on_receive__(self, packet: dict) -> None:
        try:
            self.__handle_new_node__(packet['from'])
            portnum = packet['decoded']['portnum']
            match portnum:
                case 'TEXT_MESSAGE_APP':
                    self.__handle_text_message__(packet)
                case "TELEMETRY_APP":
                    self.__handle_telemetry__(packet)
                case "POSITION_APP":
                    pass
                case _:
                    logging.info(f"Received unhandled {portnum} packet: {packet}\n")
        except UnicodeDecodeError:
            logging.error(f"Message decoding failed due to UnicodeDecodeError: {packet}")
    
    def run(self):
        def handle_shutdown_signal(signum, frame):
            logging.info(f"Received shutdown signal: {signum}. Exiting gracefully...")
            self.interface.close()
            exit(0)

        signal.signal(signal.SIGTERM, handle_shutdown_signal)
        signal.signal(signal.SIGINT, handle_shutdown_signal)

        pub.subscribe(self.__on_receive__, "meshtastic.receive")
        logging.info("Subscribed to meshtastic.receive")
        try:
            while True:
                sys.stdout.flush()
                self.__load_local_nodes__()
                time.sleep(1)
        except KeyboardInterrupt:
            self.interface.close()
            logging.info("====== MeshtasticListener Exiting ======")
            exit(0)


if __name__ == "__main__":
    device = environ.get("DEVICE_INTERFACE")
    if device is None:
        raise ValueError("DEVICE_INTERFACE environment variable is not set")

    try:
        # IP address
        if '.' in device and len(device.split('.')) == 4:
            interface = TCPInterface(hostname=device)
        # Serial port path
        elif device.startswith('/') or device.startswith('COM'):
            interface = SerialInterface(device)
        else:
            raise ValueError("Invalid DEVICE_INTERFACE value. Must be a hostname or serial port path.")
    except ConnectionRefusedError:
        logging.error(f"Connection to {device} refused. Exiting...")
        exit(1)
    logging.info(f'Connected to {interface.__class__.__name__} device: {device}')

    # sanitizing the db_path
    db_path = environ.get("DB_NAME", ':memory:')
    if db_path != ':memory:':
        if not db_path.endswith('.db'):
            raise ValueError("DB_NAME must be a .db file")
        if '/' in db_path or '\\' in db_path:
            raise ValueError("DB_NAME must be a filename only")

    db_object = ListenerDb(
        db_path=path.join(data_dir, db_path))

    cmd_handler = CommandHandler(
        prefix=environ.get("CMD_PREFIX", '!'),
        cmd_db=db_object)

    listener = MeshtasticListener(
        interface=interface,
        db_object=db_object,
        cmd_handler=cmd_handler,
        node_update_interval=int(environ.get("NODE_UPDATE_INTERVAL", 15)),
        response_char_limit=int(environ.get("RESPONSE_CHAR_LIMIT", 220)),
        welcome_message=environ.get("WELCOME_MESSAGE")
    )
    
    listener.run()
