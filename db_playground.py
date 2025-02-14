from meshtastic_listener.db_utils import ListenerDb

db = ListenerDb('/Users/michaelgillett/Desktop/listner.db')
response = db.get_neighbors(source_node_id=1128078592, lookback_hours=999999999)
print(response)
