import logging
import inspect

from meshtastic_listener.data_structures import MessageReceived
from meshtastic_listener.db_utils import ListenerDb
from meshtastic_listener.position_utils import meters_to_miles

logger = logging.getLogger(__name__)

class CommandHandler:
    # all command functions need to start with cmd_ to be recognized as commands
    # all command functions need to have a docstring to be recognized as a command
    def __init__(
            self,
            cmd_db: ListenerDb,
            prefix: str = '!',
            bbs_lookback: int = 7,
            admin_node_id: str | None = None,
            character_limit: int = 200
        ) -> None:

        self.prefix = prefix
        self.db = cmd_db
        self.bbs_lookback = bbs_lookback
        self.admin_node_id = admin_node_id
        self.char_limit = character_limit

    def __is_admin__(self, node_id: str) -> bool:
        if self.admin_node_id is None:
            logger.error('Admin node not set. Cannot check if node is an admin.')
            return False
        elif str(node_id) != str(self.admin_node_id):
            logger.warning(f'{node_id} is not authorized')
            return False
        else:
            logger.info(f'{node_id} authenticated as admin')
            return True

    def cmd_reply(self, context: MessageReceived) -> str:
        '''
        !reply - Reply with the current hop count and signal strength
        '''
        logger.info('Reply command received')
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
        if self.__is_admin__(context.fromId) is False:
            return 'You are not authorized to clear the BBS'
        else:
            self.db.soft_delete_annoucements()
            return 'BBS Cleared'
        
    def cmd_closest(self, n_nodes: int = 5) -> str:
        '''
        !closest - Report the closest nodes to server
        '''
        nodes = self.db.get_closest_nodes(n_nodes=n_nodes)
        if len(nodes) == 0:
            logging.error('Unable to find any nodes with calculated positions')
            return 'No nodes with calculated positions found'
        
        logger.info(f'Closest nodes: {nodes}')
        response_str = 'Closest nodes:\n'
        for i, node in enumerate(nodes):
            response_str += f'{i+1}. {node.shortName} - {meters_to_miles(node.distance)} miles\n'
        return response_str

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

    def handle_command(self, context: MessageReceived) -> str | None:
        if context.decoded.text.startswith(self.prefix):
            command = context.decoded.text[1:].lower().split(' ')[0]
            match command:
                case 'help':
                    return self.cmd_help()
                
                case 'reply':
                    return self.cmd_reply(context)
                
                case 'post':
                    return self.cmd_post(context)
                
                case 'read':
                    return self.cmd_read()
                
                case 'clear':
                    return self.cmd_clear(context)
                
                case 'closest':
                    return self.cmd_closest()

                case _:
                    logger.error(f'Unknown command: {command}')
                    return f'Unknown command: {command}'
        else:
            return None
