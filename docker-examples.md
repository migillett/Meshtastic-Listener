# Docker-Compose Examples

I've included a few docker-compose examples for how to run the Meshtastic-Listener BBS alongside other services.

> [!TIP]
> Make sure you rename your `secrets_example.env` either to `.env` or rename the `.env` file below to make sure you're pulling in the correct file. I'd also recommend modify the permissions of this file to something like `chmod 600 ./.env` to prevent any unwanted eyes at your configuration and passwords.


## Full-Stack with Meshtasticd Firmware
There are some instances where you need to run the [Meshtastic firmware](https://github.com/meshtastic/firmware) and have it control local hardware. For example, the [MeshAdv Pi Hat](https://github.com/chrismyers2000/MeshAdv-Pi-Hat). I have this exact setup for my local node and here's what I have running.

One note is that you'll want to set the environment variable `DEVICE_IP` to the name of the `meshtasticd` firmware docker container. The hostname is more than sufficient, no inter-docker network IP required.

> [!TIP]
> There are other installation instructions besides this docker-compose file including SPI and I2C. See the [Meshtastic webiste](https://meshtastic.org/docs/software/linux/installation/) for more details on how to get that working.

```yaml
services:
  meshtasticd:
    image: meshtastic/meshtasticd:beta-debian
    container_name: meshtasticd
    devices:
      - "/dev/spidev0.0"
      - "/dev/gpiochip0"
    cap_add:
      - SYS_RAWIO
    ports:
      - 4403:4403
    volumes:
      - ./meshtasticd/config.yaml:/etc/meshtasticd/config.yaml:ro
      - ./meshtasticd/data:/var/lib/meshtasticd
    restart: unless-stopped

  meshtastic_listener:
    depends_on:
      - listener_db
      - meshtasticd
    build:
      context: ./Meshtastic-Listener
      dockerfile: dockerfile
    container_name: meshtastic_listener
    user: "1000:1000"
    env_file:
      - .env
    restart: unless-stopped

  listener_db:
    image: postgres:latest
    container_name: listener_db
    ports:
      - 5432:5432
    shm_size: 256mb
    volumes:
      - ./db:/var/lib/postgresql/data
    env_file:
      - .env
    restart: unless-stopped

  adminer:
    image: adminer
    container_name: adminer
    depends_on:
      - listener_db
    restart: unless-stopped
    ports:
      - 8080:8080
```

## USB Passthrough
If you're using a radio connected to your local computer via USB, you'll need to include a few specific changes to your docker compose file.

- Ensure that your `DEVICE_IP` is un-set in your environment variables. If unset, it'll default to trying to connect to your radio via serial.
- You'll want to pass through your USB device into the meshtastic_listener container using `devices:` (see below). You can use `lsusb` on linux to help find that device is where. I've had best luck with `tty0`. If you're on Windows, you may need to do `COM{x}` instead.

```yaml
services:
  meshtastic_listener:
    depends_on:
      - listener_db
      - meshtasticd
    devices:
      - /dev/tty0:/dev/tty0
    build:
      context: ./Meshtastic-Listener
      dockerfile: dockerfile
    container_name: meshtastic_listener
    user: "1000:1000"
    env_file:
      - .env
    restart: unless-stopped

  listener_db:
    image: postgres:latest
    container_name: listener_db
    ports:
      - 5432:5432
    shm_size: 256mb
    volumes:
      - ./db:/var/lib/postgresql/data
    env_file:
      - .env
    restart: unless-stopped

  adminer:
    image: adminer
    container_name: adminer
    depends_on:
      - listener_db
    restart: unless-stopped
    ports:
      - 8080:8080
```

## Connecting Via IP
This is very similar to the USB Passthrough example, except you won't need to pass through a device. Just modify your `.env` file and make sure to specify your node's IP address under `DEVICE_IP`. I HIGHLY recommend setting a static IP address for your radio otherwise you may face radio disconnection issues.

```yaml
services:
  meshtastic_listener:
    depends_on:
      - listener_db
      - meshtasticd
    build:
      context: ./Meshtastic-Listener
      dockerfile: dockerfile
    container_name: meshtastic_listener
    user: "1000:1000"
    env_file:
      - .env
    restart: unless-stopped

  listener_db:
    image: postgres:latest
    container_name: listener_db
    ports:
      - 5432:5432
    shm_size: 256mb
    volumes:
      - ./db:/var/lib/postgresql/data
    env_file:
      - .env
    restart: unless-stopped

  adminer:
    image: adminer
    container_name: adminer
    depends_on:
      - listener_db
    restart: unless-stopped
    ports:
      - 8080:8080
```