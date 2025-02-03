FROM python:3.13-bookworm

WORKDIR /home/meshtastic

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# where we store the database file and logs
RUN mkdir ./data

COPY ./pyproject.toml .
RUN pip3 install poetry && \
    poetry install --no-root

COPY ./meshtastic_listener ./meshtastic_listener

ENTRYPOINT [ "poetry", "run", "python", "-m", "meshtastic_listener" ]
