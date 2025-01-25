from time import time

from meshtastic_listener.functions.db_utils import CommandHandlerDb


def test_db_functions():
    db = CommandHandlerDb(':memory:')

    message = {
        'fromId': 1,
        'toId': 2,
        'fromName': 'TEST',
        'message': 'Hello, World!',
        'rxTime': int(time()),
        'rxSnr': 10.0,
        'rxRssi': -50,
        'hopStart': 1,
        'hopLimit': 2,
    }

    # Insert a message
    db.insert_annoucement(message)
    annoucements = db.get_annoucements()
    # make sure the response matches up
    assert len(annoucements) == 1
    assert annoucements[0][0] == message['fromName']
    assert annoucements[0][1] == message['message']

    # insert test message spoofed as 25 hours in the past
    message['rxTime'] = int(time()) - 25 * 3600
    message['message'] = 'Hello, World! 25 hours ago'
    db.insert_annoucement(message)
    annoucements = db.get_annoucements(hours_past=24)
    assert len(annoucements) == 1

    # we should get 2 messages if we look back 30 hours
    a = db.get_annoucements(hours_past=30)
    assert len(a) == 2

    # insert 4 more test messages spoofed as 23 hours in the past
    for i in range(4):
        message['rxTime'] = int(time()) - 23 * 3600
        message['message'] = f'test message {i}'
        db.insert_annoucement(message)
    annoucements = db.get_annoucements(hours_past=24)
    assert len(annoucements) == 5

    print('All annoucement tests passed!')
