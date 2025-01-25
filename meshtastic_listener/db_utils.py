import sqlite3
import logging
from time import time

class CommandHandlerDb:
    # for interacting with a local sqlite database
    # used for storing messages
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        logging.info(f'CommandHandlerDb initialized with db_path: {self.db_path}')

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self) -> None:
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS annoucements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fromId INTEGER NOT NULL,
                toId INTEGER NOT NULL,
                fromName TEXT DEFAULT NULL,
                message TEXT NOT NULL,
                rxTime INTEGER NOT NULL,
                rxSnr FLOAT NOT NULL,
                rxRssi INTEGER NOT NULL,
                hopStart INTEGER NOT NULL,
                hopLimit INTEGER NOT NULL
            );
            """
        )
        self.conn.commit()
        logging.info('annoucements table created')

    def insert_annoucement(self, payload: dict) -> None:
        self.cursor.execute(
            """
            INSERT INTO annoucements (
                fromId, toId, fromName, message, rxTime, rxSnr, rxRssi, hopStart, hopLimit
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                payload['fromId'],
                payload['toId'],
                payload['fromName'],
                payload['message'],
                payload['rxTime'],
                payload['rxSnr'],
                payload['rxRssi'],
                payload['hopStart'],
                payload['hopLimit'],
            ),
        )
        self.conn.commit()
        logging.info(f'Annoucement inserted into db: {payload}')

    def get_annoucements(self, hours_past: int = 24) -> list[tuple[str, str]]:
        '''
        returns a list of tuples containing the fromName (shortname) and message of annoucements from the past n hours
        example:
        [(1, 'Hello, World!'), (2, 'Hello, World 2!')]
        '''
        logging.info(f'Fetching annoucements from db for the last {hours_past} hours')
        look_back = int(time()) - (hours_past * 3600)
        self.cursor.execute(
            """
            SELECT fromName, message FROM annoucements WHERE rxTime > ? ORDER BY rxTime DESC;
            """,
            (look_back,)
        )
        results = self.cursor.fetchall()
        logging.info(f'Successfully fetched {len(results)} annoucements')
        return results
