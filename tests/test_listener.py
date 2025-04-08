from os import path, listdir
import json
from time import time
from dataclasses import dataclass

from meshtastic_listener.__main__ import MeshtasticListener
from meshtastic_listener.cmd_handler import CommandHandler
from meshtastic_listener.listener_db.listener_db import ListenerDb, Base
from meshtastic.mesh_interface import MeshInterface

import pytest


@dataclass
class FakeMeshPacket:
    id: int

class TestInterface(MeshInterface):
    def __init__(self) -> None:
        super().__init__()
        self.localNode.nodeNum = 1234567890
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

        self.expected_response: str | None = None

    def getMyNodeInfo(self):
        return self.nodes['1234567890']

    def close(self) -> None:
        pass

    def sendText(self, text=str, destinationId=int, channelIndex=int, wantAck: bool = False) -> dict:
        print(f'Sending text:\n\n{text}\n\nto {destinationId} on channel {channelIndex}')
        if self.expected_response is not None:
            assert text.startswith(self.expected_response), f'Expected: {self.expected_response} | Received: {text}'
        else:
            print(f'No expected response set. Received:\n\n{text}')

        return FakeMeshPacket(id=1234567890)


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
    cmd_db=db
)

listener = MeshtasticListener(
    interface=test_interface,
    cmd_handler=cmd_handler,
    db_object=db,
    admin_nodes=[1234567890]
)

def test_listener():
    json_dir = path.join(path.dirname(path.abspath(__file__)), 'test_messages')
    for file in listdir(json_dir):
        if file.endswith(".json"):
            with open(path.join(json_dir, file), 'rb') as json_file:
                print(f'testing file: {file}')
                message_received = json.load(json_file)
                listener.__on_receive__(packet=message_received)

    # clear out all messages sent to the bbs
    db.soft_delete_bbs_messages()
    
    # a list of commands and the expected response from the BBS
    # we'll do a check of response.startswith(expected_response) for each command
    test_commands = [
        ('!help', ''), # this message will be long, so just check for a basic response
        ('!reply', 'hops:'),
        ('!waypoints', 'Sent 1 waypoint to your map'), # we created 1 waypoint using the JSON test above
        ('!categories', 'Categories:'),
        ('!select 1', 'No active BBS messages posted in General'),
        ('!post posting to general', 'message received'),
        ('!post posting to category 1', 'message received'),
        ('!read', 'General:'),
        ('!select 2', 'No active BBS messages posted in Annoucements'),
        ('!read', 'No active BBS messages posted in Annoucements'),
        ('!post posting to category 2', 'message received'),
        ('!read', 'Annoucements:'),
        ('!select 0', 'Category 0 does not exist'),

        # SUBSCRIPTIONS
        ('!sub', 'Subscription Commands:'),
        ('!sub ls', 'You are not subscribed to any categories'),
        ('!sub add a', 'Invalid topic. Please specify a valid category number.'),
        ('!sub add 0', 'Category 0 does not exist.'),
        ('!sub add 1', 'Subscribed to category 1'),
        ('!sub ls', 'Active Subscriptions'),
        ('!sub add 2', 'Subscribed to category 2'),
        ('!sub ls', 'Active Subscriptions'),
        ('!sub rm 1', 'Unsubscribed from category 1'),
        ('!sub rm *', 'Unsubscribed from all topics'),
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
        print(f'Sending message: {message[0]}')
        message_received['rxTime'] = int(time())
        message_received['decoded']['text'] = message[0]
        test_interface.expected_response = message[1]
        listener.__on_receive__(packet=message_received, interface=test_interface)

    # testing notifications queuing for DMs
    # TODO - add testing for when receive an ACK from the notification recipient
    print('Testing notifications queuing for DMs')
    message_received['from'] = 4567891230
    message_received['decoded']['text'] = 'testing notifications queuing'
    test_interface.expected_response = None
    listener.__on_receive__(packet=message_received, interface=test_interface)


@pytest.fixture(scope="session", autouse=True)
def run_after_tests():
    yield # wait for tests to finish
    print('Testing complete. Cleaning up db.')
    with db.session() as session:
        Base.metadata.drop_all(db.engine)
        session.commit()
