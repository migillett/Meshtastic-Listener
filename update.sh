#!/bin/bash

# simple script for pulling the latest changes from the git repository and rebuilding the docker containers
# useful for debugging and testing

git stash
git pull
git stash pop
docker compose up -d --force-recreate --build
docker system prune -af
