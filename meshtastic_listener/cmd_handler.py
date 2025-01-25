import logging
import inspect

from meshtastic_listener.data_structures import MessageReceived
from meshtastic_listener.db_utils import ListenerDb

logger = logging.getLogger(__name__)

class CommandHandler:
    # all command functions need to start with cmd_ to be recognized as commands
    # all command functions need to have a docstring to be recognized as a command
    def __init__(self, cmd_db: ListenerDb, prefix: str = '!') -> None:
        self.prefix = prefix
        logger.info(f'CommandHandler initialized with prefix: {self.prefix}')
        self.db = cmd_db

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
        if len(context.decoded.text) > 220:
            return 'Message too long. Max 220 characters'
        elif len(context.decoded.text) == 0:
            return 'Message is empty'
        self.db.insert_annoucement(context.db_payload())
        return 'message received'
    
    def cmd_read(self) -> str:
        '''
        !read - Read the last 24 hours of board messages
        '''
        response_str = 'BBS:\n'
        for i, annoucement in enumerate(self.db.get_annoucements(hours_past=24)):
            response_str += f'{i+1}. {annoucement[1]}: {annoucement[2]}\n'
        return response_str.strip('\n')

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
                
                case _:
                    logger.error(f'Unknown command: {command}')
                    return f'Unknown command: {command}'
        else:
            return None
