import logging
import inspect

from meshtastic_listener.data_structures import MessageReceived
from meshtastic_listener.db_utils import ListenerDb, Waypoints, InvalidCategory

logger = logging.getLogger(__name__)

class UnauthorizedError(Exception):
    pass

class UnknownCommandError(Exception):
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
        !post <message> - Post BBS message
        '''
        context.decoded.text = context.decoded.text.replace('!post', '').strip()
        if len(context.decoded.text) > self.char_limit:
            return f'Message too long. Max {self.char_limit} characters'
        elif len(context.decoded.text) == 0:
            return 'Message is empty'
        self.db.post_bbs_message(context)
        return 'message received'
    
    def cmd_read(self, context: MessageReceived, user_category: int | None = None) -> str:
        '''
        !read - Read BBS messages
        '''

        if user_category is None:
            try:
                user_category = self.db.get_node(node_num=context.fromId).selectedCategory
            except AttributeError:
                logger.warning(f'User {context.fromId} has not selected a category. Defaulting to 1')
                user_category = 1

        category_name = self.db.get_category_by_id(user_category).name
        response_str = f'{category_name}:\n'

        bbs_messages = self.db.get_bbs_messages(
            days_past=self.bbs_lookback,
            category_id=user_category
        )

        if len(bbs_messages) > 0:
            logger.info(f'{len(bbs_messages)} BBS messages found: {bbs_messages}')
            for i, bbs_message in enumerate(bbs_messages):
                shortname = self.db.get_shortname(bbs_message.fromId)
                response_str += f'{i+1:>2}. {shortname:<5}: {bbs_message.message}\n'
            return response_str.strip('\n')
        else:
            return f'No BBS messages posted in the last {self.bbs_lookback} days in category {category_name}'
    
    def cmd_list_categories(self) -> str:
        '''
        !categories - List available categories
        '''
        response = 'Categories:\n'
        categories = self.db.list_categories()
        if len(categories) == 0:
            return 'No categories found'
        
        for category in categories:
            response += f'{category.id}: {category.name}\n'

        return response.strip()

    def cmd_select_category(self, context: MessageReceived) -> str:
        '''
        !select <number / name> - Select a bbs category
        '''
        category = context.decoded.text.replace('!select', '').strip()
        if category.isdigit():
            category_id = int(category)
        else:
            category = self.db.get_category_by_name(category)
            if category is None:
                return f'Category {category} not found'
            category_id = category.id

        try:
            self.db.select_category(node_num=context.fromId, category_id=category_id)
            logger.info(f'User {context.fromId} navigated to category {category_id}')
            return self.cmd_read(context=context, user_category=category_id)

        except InvalidCategory as e:
            return str(e)

    def cmd_clear(self, context: MessageReceived) -> str:
        '''
        !clear - (admins only) Clear the BBS
        '''
        self.__is_admin__(context.fromId) # raises UnauthorizedError if not admin
        self.db.soft_delete_bbs_messages()
        return 'BBS cleared'
    
    def cmd_waypoints(self) -> str | list[Waypoints]:
        '''
        !waypoints - Get the waypoints of the server
        ''' 
        waypoints = self.db.get_waypoints()
        if len(waypoints) == 0:
            return 'No waypoints found'

        return waypoints
    
    def cmd_help(self, context: MessageReceived) -> str:
        '''
        !help - Display this help message
        '''
        help_str = 'Commands:'
        for name, member in inspect.getmembers(self.__class__, inspect.isfunction):
            # Check if it's a method and has a docstring
            if name.startswith('cmd_'):
                doc = inspect.getdoc(member)
                if '(admins only)' in doc and context.fromId != self.admin_node_id:
                    continue
                elif doc:
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
                    return self.cmd_read(context)
                
                case 'clear':
                    return self.cmd_clear(context)
                
                case 'categories':
                    return self.cmd_list_categories()
                
                case 'select':
                    return self.cmd_select_category(context)
                
                case 'waypoints':
                    # either returns an message "no waypoints found" or a list of Waypoints data
                    # we'll need to send that data using the interface in the __main__.py file
                    return self.cmd_waypoints()
                
                case 'help':
                    return self.cmd_help(context)

                case _:
                    logger.warning(f'Unknown command: {command}')
                    raise UnknownCommandError(f'Unknown command: {command}')
        else:
            return None
