# app/database.py
from functools import lru_cache
from os import environ
from meshtastic_listener.listener_db.listener_db import ListenerDb

@lru_cache(maxsize=1)
def get_db_instance() -> ListenerDb:
    """Get or create the database connection instance."""
    return ListenerDb(
        hostname=environ.get('POSTGRES_HOSTNAME'),
        username=environ.get('POSTGRES_USER', 'postgres'),
        password=environ.get('POSTGRES_PASSWORD'),
        db_name=environ.get('POSTGRES_DB')
    )
