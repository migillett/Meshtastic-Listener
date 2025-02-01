FROM python:3.13-bookworm

WORKDIR /home/meshtastic

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY ./meshtastic_listener ./meshtastic_listener
COPY ./pyproject.toml .

# where we store the database file and logs
RUN mkdir ./data

RUN pip3 install poetry && \
    poetry install --no-root

ENTRYPOINT [ "poetry", "run", "python", "-m", "meshtastic_listener" ]
