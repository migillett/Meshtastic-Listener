import logging
import inspect

from meshtastic_listener.data_structures import MessageReceived, NodeHealthCheck
from meshtastic_listener.commands.subscriptions import handle_subscription_command
from meshtastic_listener.listener_db.listener_db import ListenerDb, Waypoints

logger = logging.getLogger(__name__)

class UnknownCommandError(Exception):
    pass

class CommandHandler:
    # all command functions need to start with cmd_ to be recognized as commands
    # all command functions need to have a docstring to be recognized as a command
    def __init__(
            self,
            cmd_db: ListenerDb,
            server_node_id: int,
            version: str,
            prefix: str = '!'
        ) -> None:

        self.prefix = prefix
        self.db = cmd_db
        self.server_node_id = server_node_id
        self.version = version
        self.char_limit = 200

    def cmd_reply(self, context: MessageReceived) -> str:
        '''
        1: !r - rx stats
        '''
        return f'RX HOPS: {context.hopLimit} / {context.hopStart}\nRX SNR: {context.rxSnr}\nRX RSSI: {context.rxRssi}'

    def cmd_waypoints(self) -> str | list[Waypoints]:
        '''
        2: !w - Get server waypoints
        ''' 
        waypoints = self.db.get_waypoints()
        if len(waypoints) == 0:
            return 'No waypoints found'

        return waypoints

    def cmd_healthcheck(self, health_status: NodeHealthCheck | None) -> str:
        '''
        3: !c - Get node health
        '''
        if isinstance(health_status, NodeHealthCheck):
            return health_status.status()
        else:
            return 'No health check data available.'
        
    def cmd_links(self) -> str:
        '''
        4: !l - Get current node links
        '''
        links = self.db.get_listener_nodes()
        if len(links) == 0:
            return 'No links found'
        
        response = ''
        for link in links:
            connection_status = '⚠️' if link.reconnectAttempts > 0 else '☑️'
            response += f'{link.nodeNum} ({link.longName}): {link.hostSoftwareVersion} {connection_status}\n'
        return response.strip()
    
    def cmd_traceroute_health(self) -> str:
        '''
        5: !t - Get traceroute health summary
        '''
        response = ''
        nodes = self.db.get_favorite_nodes()
        if len(nodes) == 0:
            return 'No favorite nodes found'
        
        for node in nodes:
            if node.nodeNum == self.server_node_id:
                continue
            results = self.db.get_traceroute_results_by_node(
                source_id=self.server_node_id,
                target_id=node.nodeNum
            )
            if len(results) == 0:
                response += f'{node.shortName}: No traces\n'
            else:
                successes = sum(1 for r in results if r.rxTime is not None)
                response += f'{node.shortName}: {successes}/{len(results)}\n'
        return response.strip()

    # def cmd_subscriptions(self, context: MessageReceived) -> str:
    #     '''
    #     3: !s - List subscription commands
    #     '''
    #     return handle_subscription_command(
    #         context=context,
    #         db=self.db,
    #         prefix=f'{self.prefix}s'
    #     )
    
    def cmd_info(self) -> str:
        '''
        98: !i - Display info
        '''
        return f'Meshtastic Listener {self.version}\nhttps://github.com/migillett/meshtastic-listener'

    def cmd_help(self) -> str:
        '''
        99: !h - Help menu
        '''
        cmds: list[str] = []
        for name, member in inspect.getmembers(self.__class__, inspect.isfunction):
            # Check if it's a method and has a docstring
            if name.startswith('cmd_'):
                doc = inspect.getdoc(member)
                if doc:
                    cmds.append(doc)

        # sort the commands by the leading number in the docstring
        # it might be easier to just do this by hand, but this is more fun
        cmds.sort()
        return '\n'.join([c.split(': ')[-1].replace('!', self.prefix) for c in cmds]).strip()

    def handle_bell_alert(self, context: MessageReceived) -> None:
        logging.warning(f'Received Alert from {context.fromId}: {context.model_dump_json()}')

    def handle_command(
            self,
            context: MessageReceived,
            node_health: NodeHealthCheck | None
        ) -> str | None | list[Waypoints]:
        
        if context.decoded.text is not None:
            if "🔔" in context.decoded.text:
                self.handle_bell_alert(context)

            elif context.decoded.text.startswith(self.prefix):
                command = context.decoded.text[1:].lower().split(' ')[0]
                logging.info(f'Command received: {command} From: {context.fromId}')
                match command:
                    case 'r':
                        return self.cmd_reply(context)
                    
                    case 'c':
                        return self.cmd_healthcheck(node_health)

                    # case 's':
                    #     return self.cmd_subscriptions(context)

                    case 'w':
                        # either returns an message "no waypoints found" or a list of Waypoints data
                        # we'll need to send that data using the interface in the __main__.py file
                        return self.cmd_waypoints()

                    case 'l':
                        return self.cmd_links()
                    
                    case 't':
                        return self.cmd_traceroute_health()
                    
                    case 'i':
                        return self.cmd_info()
                    
                    case 'h':
                        return self.cmd_help()

                    case _:
                        logger.warning(f'Unknown command: {command}')
                        raise UnknownCommandError(f'Unknown command: {command}')
        return None
