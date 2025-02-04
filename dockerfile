FROM python:3.13-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ARG UID=1000
ARG GID=1000

RUN groupadd -g $GID meshtastic && \
    useradd -u $UID -m -g meshtastic meshtastic

USER meshtastic
ENV PATH="/home/meshtastic/.local/bin:${PATH}"
WORKDIR /home/meshtastic

COPY --chown=meshtastic:meshtastic ./pyproject.toml .
COPY --chown=meshtastic:meshtastic ./meshtastic_listener ./meshtastic_listener
RUN mkdir ./data && chown -R meshtastic:meshtastic /home/meshtastic/data

RUN pip3 install --user poetry && poetry install

HEALTHCHECK --interval=30s --timeout=3s \
    CMD [ "$(id -u)" -ne 0 ] || exit 1

ENTRYPOINT [ "poetry", "run", "python", "-m", "meshtastic_listener" ]
