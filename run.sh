#!/bin/bash
set -e

echo "Building and starting SentinelAI..."
docker compose up --build -d
echo ""
echo "SentinelAI running at http://localhost:3000"
echo "Use 'docker compose logs -f' to tail logs."
