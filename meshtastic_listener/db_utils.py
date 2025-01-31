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

    def create_table(self) -> None:
        self.cursor.executescript(
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

            CREATE TABLE IF NOT EXISTS nodes (
                num INTEGER PRIMARY KEY NOT NULL,
                longName TEXT DEFAULT NULL,
                shortName TEXT DEFAULT NULL,
                macaddr TEXT DEFAULT NULL,
                hwModel TEXT DEFAULT NULL,
                publicKey TEXT DEFAULT NULL,
                role TEXT DEFAULT NULL,
                lastHeard INTEGER DEFAULT NULL,
                hopsAway INTEGER DEFAULT NULL,
                latitude FLOAT DEFAULT NULL,
                longitude FLOAT DEFAULT NULL,
                altitiude FLOAT DEFAULT NULL,
                precisionBits INTEGER DEFAULT NULL
            );

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

            CREATE TABLE IF NOT EXISTS traceroutes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rxTime INTEGER DEFAULT CURRENT_TIMESTAMP,
                fromId INTEGER NOT NULL,
                toId INTEGER NOT NULL,
                tracerouteDetails TEXT DEFAULT NULL,
                snrAvg FLOAT DEFAULT NULL,
                directConnection BOOLEAN DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS message_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rxTime INTEGER DEFAULT CURRENT_TIMESTAMP,
                fromId INTEGER NOT NULL,
                toId INTEGER NOT NULL,
                portnum TEXT NOT NULL,
                decoded text NOT NULL
            );

            CREATE VIEW IF NOT EXISTS history_viewable AS
            SELECT 
                m.rxTime,
                from_node.longName as from_node_name,
                to_node.longName as to_node_name,
                m.portnum,
                m.decoded
            FROM message_history m
            LEFT JOIN nodes from_node ON m.fromId = from_node.num
            LEFT JOIN nodes to_node ON m.toId = to_node.num;
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

    def get_annoucements(self, days_past: int = 7) -> list[tuple[int, str, str]]:
        '''
        returns a list of tuples containing:
            1. the announcement id
            2. the author fromName (shortname)
            3. message of annoucements from the past n days
        example:
        [(1, 'NAME', 'Hello, World!'), (2, 'NAME', 'Hello, World 2!')]
        '''
        look_back = int(time()) - (days_past * 24 * 3600)
        logger.info(f'Fetching annoucements from db for the last {days_past} days')
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
        logger.info(f'Fetched {len(results)} annoucements')
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

    def upsert_position(self, node_num: int, last_heard: int, latitude: float, longitude: float, altitude: float, precision_bits: int) -> None:
        self.cursor.execute(
            """
            INSERT INTO nodes (
                num, lastHeard, latitude, longitude, altitiude, precisionBits
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(num) DO UPDATE SET
                lastHeard=excluded.lastHeard,
                latitude=excluded.latitude,
                longitude=excluded.longitude,
                altitiude=excluded.altitiude,
                precisionBits=excluded.precisionBits
            ;
            """,
            (node_num, last_heard, latitude, longitude, altitude, precision_bits,)
        )
        self.conn.commit()
        logger.info(f'Position updated for node {node_num}')

    def insert_message_history(self, packet: dict) -> None:
        self.cursor.execute(
            """
            INSERT INTO message_history (
                fromId, toId, portnum, decoded
            ) VALUES (?, ?, ?, ?)
            """, (
                packet['from'],
                packet['to'],
                packet['decoded']['portnum'],
                json.dumps(packet['decoded'], default=str, indent=2)
            ))
        self.conn.commit()
