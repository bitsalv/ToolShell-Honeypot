#!/bin/bash

echo "ToolShell-Honeypot v2.0 Deployment Menu"
echo "----------------------------------------"
echo "0) Build all Docker images"
echo "1) Start only the honeypot (sensor)"
echo "2) Start only the analyzer"
echo "3) Start only the dashboard (GUI)"
echo "4) Start honeypot + analyzer"
echo "5) Start analyzer + dashboard"
echo "6) Start all services (honeypot + analyzer + dashboard)"
echo "7) Show status"
echo "8) Stop only the honeypot"
echo "9) Stop only the analyzer"
echo "10) Stop only the dashboard"
echo "11) Stop all containers"
echo "q) Quit"
echo

read -p "Choose an option: " opt

case $opt in
  0)
    echo "Building all Docker images..."
    sudo docker-compose build
    ;;
  1)
    echo "Starting only the honeypot (sensor)..."
    sudo docker-compose up -d honeypot
    ;;
  2)
    echo "Starting only the analyzer..."
    sudo docker-compose up -d analyzer
    ;;
  3)
    echo "Starting only the dashboard (GUI)..."
    sudo docker-compose up -d dashboard
    ;;
  4)
    echo "Starting honeypot + analyzer..."
    sudo docker-compose up -d honeypot analyzer
    ;;
  5)
    echo "Starting analyzer + dashboard..."
    sudo docker-compose up -d analyzer dashboard
    ;;
  6)
    echo "Starting all services (honeypot + analyzer + dashboard)..."
    sudo docker-compose up -d
    ;;
  7)
    sudo docker-compose ps
    ;;
  8)
    echo "Stopping only the honeypot..."
    sudo docker-compose stop honeypot
    ;;
  9)
    echo "Stopping only the analyzer..."
    sudo docker-compose stop analyzer
    ;;
  10)
    echo "Stopping only the dashboard..."
    sudo docker-compose stop dashboard
    ;;
  11)
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