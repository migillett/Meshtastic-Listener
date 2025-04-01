from os import path, listdir
import json
from time import time

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
                }, 
                'position': {
                    'latitude': 33.745037,
                    'longitude': -84.390113,
                    'altitude': 0.0
                }
            }
        }

    def getMyNodeInfo(self):
        return self.nodes['1234567890']

    def close(self) -> None:
        pass

    def sendText(self, text=str, destinationId=int, channelIndex=int) -> None:
        print(f'Sending text:\n\n{text}\n\nto {destinationId} on channel {channelIndex}')


def test_listener():
    test_interface = TestInterface()

    db = ListenerDb(
        hostname='127.0.0.1',
        username='postgres',
        password='listener_db',
        db_name='listener_db'
    )

    cmd_handler = CommandHandler(
        prefix='!',
        server_node_id=1234567890,
        cmd_db=db,
        admin_node_id=1234567890,
    )
    
    listener = MeshtasticListener(
        interface=test_interface,
        cmd_handler=cmd_handler,
        db_object=db,
        admin_node=1234567890
    )

    json_dir = path.join(path.dirname(path.abspath(__file__)), 'test_messages')
    for file in listdir(json_dir):
        if file.endswith(".json"):
            with open(path.join(json_dir, file), 'rb') as json_file:
                print(f'testing file: {file}')
                message_received = json.load(json_file)
                listener.__on_receive__(packet=message_received)
    
    test_commands = [
        '!help', '!reply', 'hello world', '!clear', '!waypoints',
        '!categories', '!select 1', '!select General',
        '!post posting to general', '!post posting to category 1',
        '!read', '!select 0'
    ]

    message_received = {
        "from": 1234567890,
        "to": 1234567890,
        "decoded": {
            "portnum": "TEXT_MESSAGE_APP",
            "bitfield": 0,
            "text": ""
        },
        "id": 1234567890,
        "rxTime": 0,
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

    for message in test_commands:
        print(f'Sending message: {message}')
        message_received['rxTime'] = int(time())
        message_received['decoded']['text'] = message
        listener.__on_receive__(packet=message_received)
