import logging
import inspect
from datetime import datetime

from meshtastic_listener.data_structures import MessageReceived
from meshtastic_listener.commands.subscriptions import handle_subscription_command
from meshtastic_listener.listener_db.listener_db import ListenerDb, Waypoints, InvalidCategory

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
            prefix: str = '!'
        ) -> None:

        self.prefix = prefix
        self.db = cmd_db
        self.server_node_id = server_node_id
        self.char_limit = 200

    def cmd_reply(self, context: MessageReceived) -> str:
        '''
        1: !t - rx stats
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
        return 'Meshtastic Listener\nhttps://github.com/migillett/meshtastic-listener'

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

    def handle_command(self, context: MessageReceived) -> str | None | list[Waypoints]:
        if context.decoded.text is not None and context.decoded.text.startswith(self.prefix):
            command = context.decoded.text[1:].lower().split(' ')[0]
            logging.info(f'Command received: {command} From: {context.fromId}')
            match command:
                case 't':
                    return self.cmd_reply(context)

                # case 's':
                #     return self.cmd_subscriptions(context)

                case 'w':
                    # either returns an message "no waypoints found" or a list of Waypoints data
                    # we'll need to send that data using the interface in the __main__.py file
                    return self.cmd_waypoints()
                
                case 'i':
                    return self.cmd_info()
                
                case 'h':
                    return self.cmd_help()

                case _:
                    logger.warning(f'Unknown command: {command}')
                    raise UnknownCommandError(f'Unknown command: {command}')
        else:
            return None
