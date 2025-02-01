from time import time

from meshtastic_listener.db_utils import ListenerDb


def test_db_functions():
    db = ListenerDb(':memory:')

    message = {
        "from": 1128078592,
        "to": 1129957512,
        "decoded": {
            "portnum": "TEXT_MESSAGE_APP",
            "payload": "b'!reply'",
            "bitfield": 0,
            "text": "!reply"
        },
        "id": 675300350,
        "rxTime": 1738378320,
        "rxSnr": 6.0,
        "hopLimit": 5,
        "wantAck": True,
        "rxRssi": -58,
        "hopStart": 5,
        "publicKey": "asdfasdfasdfasdfasdfasdf=",
        "pkiEncrypted": True,
    }

    # Insert a message
    db.insert_annoucement(message)
    annoucements = db.get_annoucements()

    # make sure the response matches up
    assert len(annoucements) == 1

    assert annoucements[0].fromId == message['from']
    assert annoucements[0].toId == message['to']
    assert annoucements[0].message == message['decoded']['text']

    # insert test message spoofed as 8 days in the past
    message['rxTime'] = int(time()) - (8 * 24 * 3600)
    message['message'] = 'Hello, World! 8 days ago'
    db.insert_annoucement(message)
    annoucements = db.get_annoucements()
    assert len(annoucements) == 1

    # we should get 2 messages if we look back 10 days
    a = db.get_annoucements(days_past=10)
    assert len(a) == 2

    # insert 4 more test messages spoofed as 23 hours in the past
    for i in range(4):
        message['rxTime'] = int(time()) - 23 * 3600
        message['message'] = f'test message {i}'
        db.insert_annoucement(message)
    annoucements = db.get_annoucements()
    assert len(annoucements) == 5

    print('All annoucement tests passed!')
