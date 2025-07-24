#!/bin/bash

echo "ToolShell-Honeypot Deployment Menu"
echo "----------------------------------"
echo "0) Build all Docker images"
echo "1) Start only the honeypot"
echo "2) Start only the dashboard (GUI)"
echo "3) Start both honeypot and dashboard"
echo "4) Show status"
echo "5) Stop only the honeypot"
echo "6) Stop only the dashboard"
echo "7) Stop all containers"
echo "q) Quit"
echo

read -p "Choose an option: " opt

case $opt in
  0)
    echo "Building all Docker images..."
    sudo docker-compose build
    ;;
  1)
    echo "Starting only the honeypot..."
    sudo docker-compose up -d honeypot
    ;;
  2)
    echo "Starting only the dashboard (GUI)..."
    sudo docker-compose up -d dashboard
    ;;
  3)
    echo "Starting both honeypot and dashboard..."
    sudo docker-compose up -d
    ;;
  4)
    sudo docker-compose ps
    ;;
  5)
    echo "Stopping only the honeypot..."
    sudo docker-compose stop honeypot
    ;;
  6)
    echo "Stopping only the dashboard..."
    sudo docker-compose stop dashboard
    ;;
  7)
    echo "Stopping all containers..."
    sudo docker-compose down
    ;;
  q)
    echo "Bye!"
    exit 0
    ;;
  *)
    echo "Invalid option."
    ;;
esac 