# this is a sub-function for the !sub command that allows you to CRUD user subscriptions

from meshtastic_listener.data_structures import MessageReceived
from meshtastic_listener.listener_db.listener_db import ListenerDb, InvalidCategory
    

def handle_subscription_command(context: MessageReceived, db: ListenerDb, prefix: str = '!sub') -> str:
    '''Subscription Commands:
- ls - list subscriptions
- add <n> - subscribe to category
- rm <n> - unsubscribe from category
- rm * - unsubscribe from all categories
    '''

    subcommand = context.decoded.text.replace(prefix, '').strip()

    if subcommand == 'rm *':
        db.unsubscribe_all(node_num=context.fromId)
        return 'Unsubscribed from all topics'
    
    elif subcommand.startswith('rm '):
        try:
            category_id = int(subcommand.replace('rm ', '').strip())
            db.unsubscribe_from_category(node_num=context.fromId, category_id=category_id)
            return f'Unsubscribed from category {category_id}'
        except ValueError:
            return f'Invalid topic: {category_id}. Please specify a category number.'
    
    elif subcommand.startswith('add '):
        try:
            category_id = subcommand.replace('add ', '').strip()
            if category_id == '*':
                db.subscribe_to_all(node_num=context.fromId)
                return 'Successfully subscribed to all topics'
            else:
                category_id = int(category_id)
                db.subscribe_to_category(node_num=context.fromId, category_id=category_id)
                return f'Successfully subscribed to category {category_id}'
        except ValueError:
            return f'Invalid topic: {category_id}. Please specify a valid category number or * to subscribe to all categories.'
        except InvalidCategory as e:
            return str(e)
        
    elif subcommand == 'ls':
        subscriptions = db.list_user_subscriptions(node_num=context.fromId)
        if len(subscriptions) == 0:
            return 'You are not subscribed to any categories'
        
        response_str = 'Active Subscriptions:\n'
        for subscription in subscriptions:
            response_str += f'{subscription[0]}: {subscription[1]}\n'

        return response_str.strip()
    
    # help
    else:
        return handle_subscription_command.__doc__.strip()
