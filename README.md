# Meshtastic-Listener
One of the main things that [Meshtastic](https://meshtastic.org) is missing is a proactive way to monitor the network. Has a vital infrastructure node gone offline? Has your channel utilization reached unsafe levels for more than x amount of time? Is your node full of water? Unless you know what you're looking for and consistently check in on this data, you'll never know if something is amiss.

The goal of this repo is to solve that problem. This code will listen to your Meshtastic radio and perform healthchecks on your network on a schedule. If the mesh is in an unhealthy state and triggers a notification, it will send a text message to all admin nodes subscribed to the alert. Think of it like AWS CloudWatch, but for Meshtastic and without relying on any internet backbone.

## Commands
The listener does accept some basic commands for interfacing with the notification configuration.

- `!h` - Prints the list of commands
- `!t` - Replies to the sender with transmission details
- `!s` - Returns a list of subscription commands to handle user notifications.
- `!w` - Adds a list of waypoints from the server to your local map with a ttl of 7 days.

## To Do:
~~- Update test scripts to work with Postgres DB instead of SqLite3~~
- Add support for syncing databases between 2 nodes both running the software.
    - Consider making a "Client" version of the software that doesn't have any major functions, just the db and a web UI
- Metrics Alerting Features:
    - Paths through the network with their forward and back SNR, and RX/TX times.
    - Gather and analyze error rates for messages (what we see on the notification card on phones)
    - Temperatures and Humidity (if applicable)
    - Battery level trend over time? ie: downward trend of battery level over n days.
~~- Remove distance() functions. it's not even used anymore.~~
~~- When the user runs `!waypoints`, reply with a text message to what waypoints were sent to them.~~

## Database Information
Yes, this repo does use a Postgres database on the backend. Yes, it's overkill. Why? Because I needed to learn how to interact with Postgres for a work project. This is how I learned it. Can SQLite3 also get the job done? Absolutely. In fact, that's what the project started with. See versions 1.5.0 if you want to use that. However, I need to learn a new DB and Postgres is the name of the game.

### Viewing Database Objects
One of the main reasons for switching to Postgres was to allow for a full API frontend and database browser that was independent from the Meshtastic Listener code. The docker-compose file currently includes a conatainer for [Adminer](https://www.adminer.org/). This allows you to view the DB quickly without any additional software. This may change in the future, but it works for now.

## Installation
```bash
git clone https://github.com/migillett/Meshtastic-Listener.git
cd ./Meshtastic-Listener
python3 pip3 install poetry
poetry install
```

## Environment Variables

| Variable             | Description                                                                                       | Default       |
|----------------------|---------------------------------------------------------------------------------------------------|---------------|
| `DEVICE_IP`   | The IP address or hostname with your radio using TCP/IP.                                                       | serial auto-detect |
| `CMD_PREFIX`         | Prefix to use when triggering `cmd_handler.py`.                                                   | `!`           |
| `UPDATE_INTERVAL` | How often the service should poll for status updates. Relates to programmatic traceroutes and node database updates. | `15`          |
| `ADMIN_NODE_IDS`      | Admin node IDs with elevated permissions and service notifications. List of comma-separated node IDs as integers.                                         | `None`        |
| `ENABLE_DEBUG`       | Sets the logger to debug mode if set to `True`.                                                   | `False`       |
| `POSTGRES_DB` | The name of the Postgres database. | `listener_db` |
| `POSTGRES_PASSWORD` | The password of the user to connect to the database | No default defined |

## Infrastructure Traceroutes
An added feature for v2.0.0 includes a revamped traceroute procedure. Instead of relying on user-supplied nodes for testing connections to the rest of the infrastructure, the node queries the Postgres DB for all `ROUTER` within 5 hops. It will then attempt a traceroute at the user-defined `TRACEROUTE_INTERVAL` to a single infrastructure node.

## Docker Compose
This repo has a [Docker Compose](docker-compose.yml) file to faster deploys. You'll also want to modify the [environment secrets](secrets_example.env) for your specific use as well. For examples on various docker deployments, see the [Docker Compose Readme](docker-examples.md)

## Testing
All test scripts can be found in the `tests` directory. To run tests, you will need to startup the test database using:

```bash
docker compose -f ./tests/docker-compose.yml up
alembic upgrade head
```

Then run the test scripts using:
```bash
poetry run pytest -s
```

## Alembic Cheatsheet
Create new revision:
`alembic revision --autogenerate -m "message"`

Upgrade db to current:
`alembic upgrade head`
