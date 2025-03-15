# Meshtastic-Listener
This repo builds upon [brad28b's repo](https://github.com/brad28b/meshtastic-cli-receive-text), with some new features such as server commands and replies. This repo is meant to listen to [Meshtastic](https://meshtastic.org) nodes via TCP or Serial connections and act as a server for triggering commands. The current list of commands currently include:

- `!help` - prints the list of commands
- `!reply` - replies to the sender with transmission details
- `!post <message>` - posts a message to the board
- `!read` - get all posts to the message board from the past n days.
- `!clear` - soft deletes all messages from the BBS. Only available when a node id matches the admin id set in the env vars.
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

| Variable             | Description                                                                                       | Default       |
|----------------------|---------------------------------------------------------------------------------------------------|---------------|
| `DEVICE_INTERFACE`   | The IP address to interact with your radio.                                                       | serial auto-detect |
| `CMD_PREFIX`         | Prefix to use when triggering `cmd_handler.py`.                                                   | `!`           |
| `DB_NAME`            | Name of the SQLite database. Must end in `.db`.                                                   | `:memory:`    |
| `NODE_UPDATE_INTERVAL` | How often the service should load the local Node database to the SQLite DB in minutes.           | `15`          |
| `WELCOME_MESSAGE`    | Welcome message for new nodes on the mesh.                                                        | `None`        |
| `BBS_DAYS`           | Number of days to look back for BBS messages.                                                     | `7`           |
| `ADMIN_NODE_ID`      | Admin node ID with elevated permissions.                                         | `None`        |
| `ENABLE_DEBUG`       | Sets the logger to debug mode if set to `True`.                                                   | `False`       |
| `TRACEROUTE_NODE`    | Node to traceroute to every n hours.                                                              | `None`        |
| `TRACEROUTE_INTERVAL`| Interval (in hours) to traceroute the `TRACEROUTE_NODE`.                                          | `24`          |

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

> [!Note]
> You'll need to pass in the USB device to the container if you wish to use USB serial. For instance: `--device /dev/tty0`. Serial connections are usually `/dev/ttyUSB0` or `/dev/ttyACM0` on Linux, or `COM{x}` on Windows.

## Testing
All test scripts can be found in the `tests` directory. To run tests, use the following command:

```bash
poetry run pytest -s
```
