#!/bin/bash
# build-and-run.sh

echo "=========================================="
echo "   Building PII Guardian Docker Images    "
echo "=========================================="

# Create required directories
mkdir -p logs

# Build all Docker images
docker-compose build

echo "=========================================="
echo "   Starting PII Guardian Services         "
echo "=========================================="

# Start the system
docker-compose up -d

echo "PII Guardian started successfully."
echo "API available at http://localhost:8000"
echo ""
echo "Management interfaces:"
echo "RabbitMQ: http://localhost:15672 (guest/guest)"
echo ""
echo "To view logs: docker-compose logs -f [service_name]"
echo "To stop: docker-compose down"
echo "=========================================="
