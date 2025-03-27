from meshtastic_listener.hashing_utils import hash_incoming_message


def test_hashing():
    print(hash_incoming_message("hello", "world"))
