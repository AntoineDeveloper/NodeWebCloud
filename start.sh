#!/bin/bash
# Main loop
while true; do
  echo "Starting server..."
  node server.js

  echo "Server crashed. Restarting..."
done