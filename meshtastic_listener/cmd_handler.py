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
            prefix: str = '!',
            bbs_lookback: int = 7
        ) -> None:

        self.prefix = prefix
        self.db = cmd_db
        self.bbs_lookback = bbs_lookback
        self.server_node_id = server_node_id
        self.char_limit = 200

    def cmd_reply(self, context: MessageReceived) -> str:
        '''
        1: !t - rx stats
        '''
        return f'RX HOPS: {context.hopLimit} / {context.hopStart}\nRX SNR: {context.rxSnr}\nRX RSSI: {context.rxRssi}'

    def cmd_post(self, context: MessageReceived) -> str:
        '''
        2: !p <msg> - Post message
        '''
        context.decoded.text = context.decoded.text.replace(f'{self.prefix}p', '').strip()
        if len(context.decoded.text) > self.char_limit:
            return f'Message too long. Max {self.char_limit} characters'
        elif len(context.decoded.text) == 0:
            return 'Message is empty'
        
        # grab the poster's selected category from the db
        category = self.db.get_node_selected_category(context.fromId)
        self.db.post_bbs_message(payload=context, category_id=category.id)

        # queue notifications to all subscribed users of a given category that a new message has been posted
        subscribers = self.db.list_subscribers(category_id=category.id)
        if len(subscribers) == 0:
            logger.info(f'No subscribers found for category {category.id}: {category.name}. No notifications queued.')
        else:
            notification_message = f'{datetime.now().strftime("%d/%m/%Y: %H:%M")} | New message posted by {context.fromId} in {category.name}'
            counter = 0
            for node_num in subscribers:
                if node_num != context.fromId:
                    self.db.insert_notification(
                        to_id=node_num,
                        message=notification_message,
                    )
                    counter += 1
                else:
                    logger.info(f'Not queuing notification for {node_num} as they are the poster of the message')
            logger.info(f'Queued notifications for {counter} subscribers to category {category.id}: {category.name}')

        return f'Message posted to {category.name}'
    
    def cmd_read(self, context: MessageReceived, user_category: int | None = None) -> str:
        '''
        3: !r - Read messages
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
            logger.info(f'{len(bbs_messages)} BBS messages found')
            for i, bbs_message in enumerate(bbs_messages):
                shortname = self.db.get_shortname(bbs_message.fromId)
                response_str += f'{i+1:>2}. {shortname:<5}: {bbs_message.message}\n'
            return response_str.strip('\n')
        else:
            return f'No active BBS messages posted in {category_name}'
    
    def cmd_list_categories(self) -> str:
        '''
        4: !c - List categories
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
        5: !c <num> - Select category
        '''
        try:
            category = int(context.decoded.text.replace(f'{self.prefix}c', '').strip())
            self.db.select_category(node_num=context.fromId, category_id=int(category))
            logger.info(f'User {context.fromId} navigated to category {category}')
            return self.cmd_read(context=context, user_category=category)

        except InvalidCategory as e:
            return str(e)
        
        except ValueError:
            return 'Invalid category. Please select a number from the list of categories using !categories'
        
    def cmd_waypoints(self) -> str | list[Waypoints]:
        '''
        6: !w - Get server waypoints
        ''' 
        waypoints = self.db.get_waypoints()
        if len(waypoints) == 0:
            return 'No waypoints found'

        return waypoints
    
    def cmd_subscriptions(self, context: MessageReceived) -> str:
        '''
        7: !s - List subscription commands
        '''
        return handle_subscription_command(
            context=context,
            db=self.db,
            prefix=f'{self.prefix}s'
        )
    
    def cmd_info(self) -> str:
        '''
        98: !i - Display info
        '''
        return 'Meshtastic Listener BBS\nhttps://github.com/migillett/meshtastic-listener'

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
        if context.decoded.text.startswith(self.prefix):
            command = context.decoded.text[1:].lower().split(' ')[0]
            logging.info(f'Command received: {command} From: {context.fromId}')
            match command:
                case 't':
                    return self.cmd_reply(context)
                
                case 'p':
                    return self.cmd_post(context)
                
                case 'r':
                    return self.cmd_read(context)
                
                case 'c':
                    if context.decoded.text.strip() == '!c':
                        return self.cmd_list_categories()
                    else:
                        return self.cmd_select_category(context)

                case 's':
                    return self.cmd_subscriptions(context)

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
