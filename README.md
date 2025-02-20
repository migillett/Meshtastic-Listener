# Meshtastic-Listener
This repo builds upon [brad28b's repo](https://github.com/brad28b/meshtastic-cli-receive-text), with some new features such as server commands and replies. This repo is meant to listen to [Meshtastic](https://meshtastic.org) nodes via TCP or Serial connections and act as a server for triggering commands. The current list of commands currently include:

- `!help` - prints the list of commands
- `!reply` - replies to the sender with transmission details
- `!post <message>` - posts a message to the board
- `!read` - get all posts to the message board from the past n days.
- `!clear` - soft deletes all messages from the BBS. Only available when a node id matches the admin id set in the env vars.
- `!uplink` - returns a list of local devices sorted by signal to noise ratio (SNR).
- `!waypoints` - adds a list of waypoints from the server to your local map with a ttl of 7 days.

## To Do

## Installation
```bash
git clone https://github.com/migillett/Meshtastic-Listener.git
cd ./Meshtastic-Listener
python3 pip3 install poetry
poetry install
```

## Environment Variables
`DEVICE_INTERFACE` - (optional, default to serial auto-detect) The IP address in which you wish to interact with your radio. The software will use whatever environment variable is provided to attempt a connection. If you're doing serial and Docker deploys, don't forget to pass the serial path into the container using `devices`.

`CMD_PREFIX` - (optional, default `!`) What prefix to use when triggering `cmd_handler.py`.

`DB_NAME` - (optional, default `:memory:`) The name to the SQLite database. Names must end in `.db`. This database will be created in the `../data` in relation to the absolute path of `__main__.py`.

`NODE_UPDATE_INTERVAL` - (optional, default `15`) how often the service should load the local Node database to the SQLite DB in minutes.

`RESPONSE_CHAR_LIMIT` - (optional, default `200`) the maximum length of a message in characters before pagination.

`WELCOME_MESSAGE` - (optional str, default `None`) Whenever we see a new node on the mesh, we immediately traceroute it. Adding this environment variable will include a welcome message. Keep welcome messages under 200 characters.

`BBS_DAYS` - (optional int, default `7`) The number of days the server will look back for bulletin board service (BBS) messages. Only BBS messages posted within that window will return when someone runs `!read`.

`ADMIN_NODE_ID` - (optional int, default `None`) The admin node id that has elevated permissions to clear the BBS. Also receives service notifications for vital service messages. MUST be the full node ID as an integer, not the id that starts with `!`.

`ENABLE_DEBUG` - (optional, default `False`) Sets the logger to debug mode if set to `True`.

`TRACEROUTE_NODE` - (optional, default `None`) The node to traceroute to every n hours (see `TRACEROUTE_INTERVAL`). This is useful for keeping track of the network topology.

`TRACEROUTE_INTERVAL` - (optional, default `24`) The interval (in hours) that the host node will traceroute the `TRACEROUTE_NODE`. This is useful for keeping track of the network topology.

## Running Locally
```bash
poetry run python -m meshtastic_listener
```

## Docker Compose
This repo has a [Docker Compose](docker-compose.yml) file to faster deploys. Just modify that file with your specific environment variables and run the following command:
```bash
docker-compose up -d --force-recreate --build
```

> [!TIP]
>If you're using a I2C device such as the [MeshAdv Pi Hat](https://github.com/chrismyers2000/MeshAdv-Pi-Hat), you may need to add `network_mode: host` to your docker-compose.yml file and point your `DEVICE_INTERFACE` to `127.0.0.1` to properly connect to the local device hosted by the Raspberry Pi.

## Docker
### Build
```bash
docker build . -t meshtastic_listener:latest
```

### Run
```bash
docker run -d --rm --name meshtastic_listener -e DEVICE_INTERFACE=192.168.3.185 -e DB_NAME=listener.db -v ./data:/home/meshtastic/data meshtastic_listener:latest
```

> **Note**
You'll need to pass in the USB device to the container if you wish to use USB serial. For instance: `--device /dev/tty0`. Serial connections are usually `/dev/ttyUSB0` or `/dev/ttyACM0` on Linux, or `COM{x}` on Windows.

## Testing
All test scripts can be found in the `tests` directory. To run tests, use the following command:

```bash
poetry run pytest -s
```
