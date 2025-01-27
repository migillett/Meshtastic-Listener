import sqlite3
import logging
from time import time
import json

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
                rxTime INTEGER NOT NULL,
                fromId INTEGER NOT NULL,
                toId INTEGER NOT NULL,
                fromName TEXT DEFAULT NULL,
                message TEXT NOT NULL,
                rxSnr FLOAT NOT NULL,
                rxRssi INTEGER NOT NULL,
                hopStart INTEGER NOT NULL,
                hopLimit INTEGER NOT NULL,
                readCount INTEGER DEFAULT 0,
                isDeleted INTEGER DEFAULT 0
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
                rxTime INTEGER DEFAULT CURRENT_TIMESTAMP,
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

        # TRACEROUTE TABLE
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS traceroutes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rxTime INTEGER DEFAULT CURRENT_TIMESTAMP,
                fromId INTEGER NOT NULL,
                toId INTEGER NOT NULL,
                tracerouteDetails TEXT DEFAULT NULL,
                snrAvg FLOAT DEFAULT NULL,
                directConnection BOOLEAN DEFAULT FALSE
                );
            """
        )
        self.conn.commit()

    def insert_annoucement(self, payload: dict) -> None:
        self.cursor.execute(
            """
            INSERT INTO annoucements (
                rxTime, fromId, toId, fromName, message, rxSnr, rxRssi, hopStart, hopLimit
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                payload['rxTime'],
                payload['fromId'],
                payload['toId'],
                payload['fromName'],
                payload['message'],
                payload['rxSnr'],
                payload['rxRssi'],
                payload['hopStart'],
                payload['hopLimit'],
            ),
        )
        self.conn.commit()
        logger.info(f'Annoucement inserted into db: {payload}')

    def mark_annoucement_read(self, annoucement_ids: list[int]) -> None:
        cmd = f'UPDATE annoucements SET readCount = readCount + 1 WHERE id IN ({",".join(annoucement_ids)});'
        self.cursor.execute(cmd)
        self.conn.commit()

    def get_annoucements(self, hours_past: int = 24) -> list[tuple[int, str, str]]:
        '''
        returns a list of tuples containing:
         1. the announcement id
         2. the author fromName (shortname)
         3. message of annoucements from the past n hours
        example:
        [(1, 'NAME', 'Hello, World!'), (2, 'NAME', 'Hello, World 2!')]
        '''
        look_back = int(time()) - (hours_past * 3600)
        logger.info(f'Fetching annoucements from db for the last {hours_past} hours')
        logger.debug(f'Lookback time: rxTime > {look_back}')
        self.cursor.execute(
            """
            SELECT id, fromName, message
            FROM annoucements
            WHERE rxTime > ?
            AND isDeleted = 0
            ORDER BY rxTime DESC;
            """,
            (look_back,)
        )
        results = self.cursor.fetchall()        
        logger.info(f'Successfully fetched {len(results)} annoucements')
        self.mark_annoucement_read([str(x[0]) for x in results])
        return results
    
    def soft_delete_annoucements(self) -> None:
        logger.info('Soft deleting all annoucements')
        self.cursor.execute("UPDATE annoucements SET isDeleted = 1;")
        self.conn.commit()

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

    def insert_traceroute(
            self,
            fromId: str,
            toId: str,
            traceroute_dict: dict,
            snr_avg: float,
            direct_connection: bool) -> None:
        self.cursor.execute(
            """
            INSERT INTO traceroutes (
                fromId, toId, tracerouteDetails, snrAvg, directConnection
            ) VALUES (?, ?, ?, ?, ?)
            """, (
                fromId,
                toId,
                json.dumps(traceroute_dict, default=str),
                snr_avg,
                direct_connection,
            ))
        self.conn.commit()
        logger.info(f'Traceroute inserted into db: {fromId} -> {toId}')
