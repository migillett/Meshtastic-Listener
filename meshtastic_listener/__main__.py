import time
import sys
from os import environ, path, mkdir

import logging

from meshtastic_listener.db_utils import CommandHandlerDb
from meshtastic_listener.cmd_handler import CommandHandler
from meshtastic_listener.data_structures import MessageReceived, NodeBase

from pubsub import pub
from meshtastic.tcp_interface import TCPInterface
from meshtastic.serial_interface import SerialInterface
import toml


# the `/data` directory is for storing logs and .db files
abs_path = path.dirname(path.abspath(__file__))
data_dir = path.join(abs_path, 'data')
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
    def __init__(self, interface: TCPInterface | SerialInterface, cmd_handler: CommandHandler | None) -> None:
        version = toml.load('pyproject.toml')['tool']['poetry']['version']
        logging.info(f"====== Initializing MeshtasticListener v{version} ======")
        logging.info(f"Device Interface: {interface.__class__.__name__}")
        self.interface = interface
        self.cmd_handler = cmd_handler
        self.nodes: dict[str: NodeBase] = self.__get_nodes__()
        self.history = []

    def __get_nodes__(self) -> dict[str: NodeBase]:
        logging.info("Parsing node info...")
        nodes = {}
        for node in self.interface.nodes.values():
            nodes[str(node['num'])] = NodeBase(**node)
        logging.info(f"Parsed {len(nodes)} node details.")
        return nodes
    
    def __get_shortname__(self, node_num: int) -> str:
        node_details = self.nodes.get(str(node_num))
        if node_details:
            return str(node_details.user.shortName)
        return str(node_num)
    
    def __handle_text_message__(self, packet: dict) -> None:
        # remap keys to match the MessageReceived model
        packet['fromId'] = packet['from']
        packet['toId'] = packet['to']
        sender = self.__get_shortname__(packet['fromId'])
        payload = MessageReceived(fromName=sender, **packet)

        logging.info(f"Message Received: {payload.fromName} - {payload.decoded.payload}")
        self.history.append(payload)

        if self.cmd_handler is not None:
            response = self.cmd_handler.handle_command(context=payload)
            if response is not None:
                logging.info(f'Replying to {payload.fromId}: {response}')
                self.interface.sendText(
                    text=response,
                    destinationId=payload.fromId,
                    channelIndex=0
                )

        else:
            logging.error("Command Handler not initialized. Cannot reply to message.")
    
    def __on_receive__(self, packet: dict) -> None:
        try:
            packet.pop('raw', None)
            portnum = packet['decoded']['portnum']
            match portnum:
                case 'TEXT_MESSAGE_APP':
                    self.__handle_text_message__(packet)
                case _:
                    logging.info(f"Received unhandled {portnum} packet: {packet}")

        # except KeyError as e:
        #     logging.error(f"Message decoding failed due to KeyError: {packet} - {e}")
        except UnicodeDecodeError:
            logging.error(f"Message decoding failed due to UnicodeDecodeError: {packet}")
    
    def run(self):
        pub.subscribe(self.__on_receive__, "meshtastic.receive")
        logging.info("Subscribed to meshtastic.receive")
        try:
            while True:
                sys.stdout.flush()
                time.sleep(1)
        except KeyboardInterrupt:
            self.interface.close()
            logging.info("====== MeshtasticListener Exiting ======")
            exit(0)


if __name__ == "__main__":
    device = environ.get("DEVICE_INTERFACE")
    if device is None:
        raise ValueError("DEVICE_INTERFACE environment variable is not set")
    logging.info(f'Connecting to device: {device}')

    # IP address
    if '.' in device and len(device.split('.')) == 4:
        interface = TCPInterface(hostname=device)

    # Serial port path
    elif device.startswith('/') or device.startswith('COM'):
        interface = SerialInterface(device)

    else:
        raise ValueError("Invalid DEVICE_INTERFACE value. Must be a hostname or serial port path.")
    
    # sanitizing the db_path
    db_path = environ.get("DB_NAME", ':memory:')
    if db_path != ':memory:':
        if not db_path.endswith('.db'):
            raise ValueError("DB_NAME must be a .db file")
        if '/' in db_path or '\\' in db_path:
            raise ValueError("DB_NAME must be a filename only")

    handler_db = CommandHandlerDb(
        db_path=db_path
    )

    handler = CommandHandler(
        prefix=environ.get("CMD_PREFIX", '!'),
        cmd_db=handler_db
    )

    listener = MeshtasticListener(
        interface=interface,
        cmd_handler=handler
    )
    
    listener.run()
