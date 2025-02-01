from meshtastic_listener.__main__ import MeshtasticListener
from meshtastic_listener.cmd_handler import CommandHandler
from meshtastic_listener.db_utils import ListenerDb

from meshtastic.mesh_interface import MeshInterface


class TestInterface(MeshInterface):
    def __init__(self) -> None:
        super().__init__()
        self.nodes = {
            '1234567890': {
                'num': 1234567890,
                'user': {
                    'id': '1234567890',
                    'shortName': 'TEST',
                    'longName': 'TEST'
                }
            }
        }

    def close(self) -> None:
        pass

    def sendText(self, text=str, destinationId=int, channelIndex=int) -> None:
        print(f'Sending text: {text} to {destinationId} on channel {channelIndex}')


def test_listener():
    test_interface = TestInterface()

    handler_db = ListenerDb(
        db_path=":memory:"
    )

    cmd_handler = CommandHandler(
        prefix='!',
        cmd_db=handler_db,
        admin_node_id=1234567890,
    )
    
    listener = MeshtasticListener(
        interface=test_interface,
        cmd_handler=cmd_handler,
        db_object=handler_db
    )
    
    test_messages = [
        b'!help', b'!post Hello, World!', b'!read', b'!reply', b'hello world', b'!clear'
    ]

    message_received = {
        "from": 1234567890,
        "to": 1234567890,
        "decoded": {
            "portnum": "TEXT_MESSAGE_APP",
            "payload": b"",
            "bitfield": 0,
            "text": ""
        },
        "id": 1234567890,
        "rxTime": 1737489128,
        "rxSnr": 6.75,
        "hopLimit": 7,
        "wantAck": True,
        "rxRssi": -35,
        "hopStart": 7,
        "publicKey": "asdfasdfasdfasdfasdfasdfasdf=",
        "pkiEncrypted": True,
        "fromId": "!12345678",
        "toId": "!12345678"
    }

    for message in test_messages:
        print(f'Sending message: {message}')
        message_received['decoded']['payload'] = message
        message_received['decoded']['text'] = message.decode()
        listener.__on_receive__(packet=message_received)
    
    print('Sending position message')
    message_received['decoded'] = {
        "portnum": "POSITION_APP",
        "bitfield": 1,
        "position": {
            "latitudeI": 341,
            "longitudeI": -844,
            "altitude": 300,
            "time": 1738256931,
            "locationSource": "LOC_EXTERNAL",
            "groundSpeed": 0,
            "groundTrack": 0,
            "precisionBits": 13,
            "latitude": 34.1,
            "longitude": -84.4
        }
    }

    listener.__on_receive__(packet=message_received)
