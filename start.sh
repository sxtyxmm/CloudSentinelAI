#!/bin/bash

# CloudSentinelAI Quick Start Script
# This script helps you quickly set up and start the CloudSentinelAI system

set -e

echo "🚀 CloudSentinelAI Quick Start"
echo "================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env file created"
    echo "⚠️  Please update .env with your configuration before production use"
    echo ""
fi

# Create necessary directories
echo "📁 Creating data directories..."
mkdir -p data/raw data/processed data/models logs
echo "✅ Directories created"
echo ""

# Start Docker Compose
echo "🐳 Starting Docker containers..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo "✅ Services are running!"
    echo ""
    echo "🌐 Access the application:"
    echo "   Dashboard:    http://localhost:3000"
    echo "   API Docs:     http://localhost:8000/docs"
    echo "   Health Check: http://localhost:8000/health"
    echo ""
    echo "📊 View logs:"
    echo "   docker-compose logs -f"
    echo ""
    echo "🛠️  Initialize database (optional):"
    echo "   docker-compose exec backend python scripts/init_db.py"
    echo ""
    echo "Default credentials (after init_db.py):"
    echo "   Admin:   username=admin,   password=admin123"
    echo "   Analyst: username=analyst, password=analyst123"
    echo "   Viewer:  username=viewer,  password=viewer123"
    echo ""
    echo "⚠️  Change these passwords in production!"
    echo ""
    echo "🛑 To stop the system:"
    echo "   docker-compose down"
    echo ""
    echo "✨ CloudSentinelAI is ready to protect your cloud!"
else
    echo "❌ Failed to start services. Check logs with:"
    echo "   docker-compose logs"
    exit 1
fi
