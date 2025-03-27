import xxhash

def hash_incoming_message(message: str, from_node: str) -> str:
    return xxhash.xxh64(f"{from_node}{message}").hexdigest()
