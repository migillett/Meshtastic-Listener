import logging
import inspect

from meshtastic_listener.data_structures import MessageReceived
from meshtastic_listener.db_utils import ListenerDb, Waypoints

logger = logging.getLogger(__name__)

class UnauthorizedError(Exception):
    pass

class CommandHandler:
    # all command functions need to start with cmd_ to be recognized as commands
    # all command functions need to have a docstring to be recognized as a command
    def __init__(
            self,
            cmd_db: ListenerDb,
            server_node_id: int,
            prefix: str = '!',
            bbs_lookback: int = 7,
            admin_node_id: str | None = None,
        ) -> None:

        self.prefix = prefix
        self.db = cmd_db
        self.bbs_lookback = bbs_lookback
        self.server_node_id = server_node_id
        self.admin_node_id = admin_node_id
        self.char_limit = 200

    def __is_admin__(self, node_id: str) -> None:
        if self.admin_node_id is None:
            logger.warning('Admin node not set. Cannot check if node is an admin.')
            raise UnauthorizedError('Admin node not set. Cannot check if node is an admin.')
        elif str(node_id) != str(self.admin_node_id):
            raise UnauthorizedError(f'{node_id} is not authorized as admin')
        else:
            logger.info(f'{node_id} authenticated as admin')

    def cmd_reply(self, context: MessageReceived) -> str:
        '''
        !reply - Reply with the current hop count and signal strength
        '''
        return f'hops: {context.hopStart} / {context.hopLimit}\nrxSnr: {context.rxSnr}\nrxRssi: {context.rxRssi}'

    def cmd_post(self, context: MessageReceived) -> str:
        '''
        !post <message> - Post a message to the board
        '''
        context.decoded.text = context.decoded.text.replace('!post', '').strip()
        if len(context.decoded.text) > self.char_limit:
            return f'Message too long. Max {self.char_limit} characters'
        elif len(context.decoded.text) == 0:
            return 'Message is empty'
        self.db.insert_annoucement(context)
        return 'message received'
    
    def cmd_read(self) -> str:
        '''
        !read - Read board messages
        '''
        response_str = 'BBS:\n'
        annoucements = self.db.get_annoucements(days_past=self.bbs_lookback)
        if len(annoucements) > 0:
            logger.info(f'{len(annoucements)} BBS messages found: {annoucements}')
            for i, annoucement in enumerate(annoucements):
                shortname = self.db.get_shortname(annoucement.fromId)
                response_str += f'{i+1}. {shortname}: {annoucement.message}\n'
            return response_str.strip('\n')
        else:
            return f'No BBS messages posted in the last {self.bbs_lookback} days'
        
    def cmd_clear(self, context: MessageReceived) -> str:
        '''
        !clear - (admins only) Clear the BBS
        '''
        self.__is_admin__(context.fromId) # raises UnauthorizedError if not admin
        self.db.soft_delete_annoucements()
        return 'BBS cleared'
    
    def cmd_waypoints(self) -> str | list[Waypoints]:
        '''
        !waypoints - Get the waypoints of the server
        ''' 
        waypoints = self.db.get_waypoints()
        if len(waypoints) == 0:
            return 'No waypoints found'

        return waypoints
    
    def cmd_help(self) -> str:
        '''
        !help - Display this help message
        '''
        help_str = 'Commands:'
        for name, member in inspect.getmembers(self.__class__, inspect.isfunction):
            # Check if it's a method and has a docstring
            if name.startswith('cmd_'):
                doc = inspect.getdoc(member)
                if doc:
                    help_str += f'\n  {doc}'
        return help_str

    def handle_command(self, context: MessageReceived) -> str | None | list[Waypoints]:
        if context.decoded.text.startswith(self.prefix):
            command = context.decoded.text[1:].lower().split(' ')[0]
            logging.info(f'Command received: {command} From: {context.fromId}')
            match command:
                case 'reply':
                    return self.cmd_reply(context)
                
                case 'post':
                    return self.cmd_post(context)
                
                case 'read':
                    return self.cmd_read()
                
                case 'clear':
                    return self.cmd_clear(context)
                
                case 'uplink':
                    return self.cmd_uplink()
                
                case 'waypoints':
                    # either returns an message "no waypoints found" or a list of Waypoints data
                    # we'll need to send that data using the interface in the __main__.py file
                    return self.cmd_waypoints()
                
                case 'help':
                    return self.cmd_help()

                case _:
                    logger.warning(f'Unknown command: {command}')
                    return f'Unknown command: {command}'
        else:
            return None
