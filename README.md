# Meshtastic-Listener
This repo builds upon [brad28b's repo](https://github.com/brad28b/meshtastic-cli-receive-text), with some new features such as server commands and replies. This repo is meant to listen to [Meshtastic](https://meshtastic.org) nodes via TCP or Serial connections and act as a server for triggering commands. The current list of commands currently include:

- `!help` - Prints the list of commands
- `!reply` - Replies to the sender with transmission details
- `!post <message>` - Posts a message to the board
- `!list` - Lists all available categories on the BBS.
- `!select <id>` - Allows you to change your default category to the ID selected. Returns all messages for that category.
- `!read` - Get all posts to the message board from the past n days.
- `!waypoints` - Adds a list of waypoints from the server to your local map with a ttl of 7 days.

## To Do:
~~- Update test scripts to work with Postgres DB instead of SqLite3~~
- Add support for syncing databases between 2 nodes both running the BBS software.
- Experiment with running a MQTT server and Meshtastic Map inside the docker-compose files.

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
| `NODE_UPDATE_INTERVAL` | How often the service should load the local Node database to the SQLite DB in minutes.           | `15`          |
| `WELCOME_MESSAGE`    | Welcome message for new nodes on the mesh.                                                        | `None`        |
| `BBS_DAYS`           | Number of days to look back for BBS messages.                                                     | `7`           |
| `ADMIN_NODE_ID`      | Admin node ID with elevated permissions.                                         | `None`        |
| `ENABLE_DEBUG`       | Sets the logger to debug mode if set to `True`.                                                   | `False`       |
| `TRACEROUTE_NODE_ID`    | Node to traceroute to every n hours.                                                              | `None`        |
| `TRACEROUTE_INTERVAL`| Interval (in hours) to traceroute the `TRACEROUTE_NODE_ID`.                                          | `24`          |
| `POSTGRES_DB` | The name of the Postgres database. | `listener_db` |
| `POSTGRES_PASSWORD` | The password of the user to connect to the database | No default defined |
| `DEFAULT_CATEGORIES` | The BBS categories (pages) you wish to create by default. Comma-deleniated | `General` |

## Docker Compose
This repo has a [Docker Compose](docker-compose.yml) file to faster deploys. You'll also want to modify the [environment secrets](secrets_example.env) for your specific use as well. For examples on docker deployments, see the [Docker Compose Readme](docker-examples.me)

## Testing
All test scripts can be found in the `tests` directory. To run tests, you will need to startup the test database using:

```bash
docker compose -f ./tests/docker-compose.yml up
```

Then run the test scripts using:
```bash
poetry run pytest -s
```
