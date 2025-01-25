# Meshtastic-Listener
This repo builds upon [brad28b's repo](https://github.com/brad28b/meshtastic-cli-receive-text), with some new features such as server commands and replies. This repo is meant to listen to [Meshtastic](https://meshtastic.org) nodes via TCP or Serial connections and act as a server for triggering commands. The current list of commands currently include:

- !help - prints the list of commands
- !reply - replies to the sender with transmission details
- !post - posts a message to the board
- !read - get all posts to the message board from the past n hours.

## To Do

## Installation
```bash
git clone https://github.com/migillett/Meshtastic-Listener.git
cd ./Meshtastic-Listener
python3 pip3 install poetry
poetry install
```

## Environment Variables
`DEVICE_INTERFACE` - The interace in which you wish to interact with your radio. Can either be an IPV4 address (`192.168.x.x`) or a serial path (`/dev/ttyUSBx`). The software will use whatever environment variable is provided to attempt a connection.

`CMD_PREFIX` - (optional) What you want the command prefix to trigger the `cmd_handler.py`. Default is `!`.

`DB_NAME` - (optional) The name to the SQLite database. Default is `:memory:`. Names must end in `.db`. This database will be created in the `./data`.

## Running Locally
```bash
poetry run python -m meshtastic_listener
```

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
