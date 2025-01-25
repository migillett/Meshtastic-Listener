import sqlite3
import logging
from time import time

from meshtastic_listener.data_structures import NodeBase, DeviceMetrics


logger = logging.getLogger(__name__)

class ListenerDb:
    # for interacting with a local sqlite database
    # used for storing messages
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_table()
        logger.info(f'ListenerDb initialized with db_path: {self.db_path}')

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

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                num INTEGER PRIMARY KEY NOT NULL,
                longName TEXT DEFAULT NULL,
                shortName TEXT DEFAULT NULL,
                macaddr TEXT DEFAULT NULL,
                hwModel TEXT DEFAULT NULL,
                publicKey TEXT DEFAULT NULL,
                role TEXT DEFAULT NULL,
                lastHeard INTEGER DEFAULT NULL,
                hopsAway INTEGER DEFAULT NULL
            );
            """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nodeNum INTEGER NOT NULL,
                batteryLevel INTEGER DEFAULT NULL,
                voltage FLOAT DEFAULT NULL,
                channelUtilization FLOAT DEFAULT NULL,
                airUtilTx FLOAT DEFAULT NULL,
                uptimeSeconds INTEGER DEFAULT NULL,
                numPacketsTx INTEGER DEFAULT NULL,
                numPacketsRx INTEGER DEFAULT NULL,
                numPacketsRxBad INTEGER DEFAULT NULL,
                numOnlineNodes INTEGER DEFAULT NULL,
                numTotalNodes INTEGER DEFAULT NULL,
                numRxDupe INTEGER DEFAULT NULL,
                numTxRelay INTEGER DEFAULT NULL,
                numTxRelayCanceled INTEGER DEFAULT NULL
            );
            """
        )
        self.conn.commit()


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
        logger.info(f'Annoucement inserted into db: {payload}')

    def get_annoucements(self, hours_past: int = 24) -> list[tuple[str, str]]:
        '''
        returns a list of tuples containing the fromName (shortname) and message of annoucements from the past n hours
        example:
        [(1, 'Hello, World!'), (2, 'Hello, World 2!')]
        '''
        logger.info(f'Fetching annoucements from db for the last {hours_past} hours')
        look_back = int(time()) - (hours_past * 3600)
        self.cursor.execute(
            """
            SELECT fromName, message FROM annoucements WHERE rxTime > ? ORDER BY rxTime DESC;
            """,
            (look_back,)
        )
        results = self.cursor.fetchall()
        logger.info(f'Successfully fetched {len(results)} annoucements')
        return results
    
    def insert_nodes(self, nodes: list[NodeBase]) -> None:
        for node in nodes:
            self.cursor.execute(
                """
                INSERT INTO nodes (
                    num, longName, shortName, macaddr, hwModel, publicKey, role, lastHeard, hopsAway
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(num) DO UPDATE SET
                    longName=excluded.longName,
                    shortName=excluded.shortName,
                    macaddr=excluded.macaddr,
                    hwModel=excluded.hwModel,
                    publicKey=excluded.publicKey,
                    role=excluded.role,
                    lastHeard=excluded.lastHeard,
                    hopsAway=excluded.hopsAway;
                """,
                (
                    node.num,
                    node.user.longName,
                    node.user.shortName,
                    node.user.macaddr,
                    node.user.hwModel,
                    node.user.publicKey,
                    node.user.role,
                    node.lastHeard,
                    node.hopsAway,
                ),
            )
        self.conn.commit()
        logger.info(f'Upserted {len(nodes)} records into nodes table.')

    def get_node_shortname(self, node_num: int) -> str:
        self.cursor.execute(
            """
            SELECT shortName FROM nodes WHERE num = ?;
            """,
            (node_num,)
        )
        result = self.cursor.fetchone()
        if result:
            return result[0]
        return str(node_num)
    
    def check_node_exists(self, node_num: int) -> bool:
        self.cursor.execute(
            """
            SELECT num FROM nodes WHERE num = ?;
            """,
            (node_num,)
        )
        result = self.cursor.fetchone()
        return result is not None
    
    def insert_metrics(self, node_num: int, metrics: DeviceMetrics) -> None:
        self.cursor.execute(
            """
            INSERT INTO metrics (
                nodeNum, batteryLevel, voltage, channelUtilization,
                airUtilTx, uptimeSeconds, numPacketsTx, numPacketsRx,
                numPacketsRxBad, numOnlineNodes, numTotalNodes, numRxDupe,
                numTxRelay, numTxRelayCanceled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                node_num,
                metrics.batteryLevel,
                metrics.voltage,
                metrics.channelUtilization,
                metrics.airUtilTx,
                metrics.uptimeSeconds,
                metrics.numPacketsTx,
                metrics.numPacketsRx,
                metrics.numPacketsRxBad,
                metrics.numOnlineNodes,
                metrics.numTotalNodes,
                metrics.numRxDupe,
                metrics.numTxRelay,
                metrics.numTxRelayCanceled,
            ))
        self.conn.commit()
