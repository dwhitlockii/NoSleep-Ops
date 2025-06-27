#!/bin/bash

# NoSleep-Ops Web Attack Monitor Startup Script
echo "🚀 Starting NoSleep-Ops Web Attack Monitor..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Check if web-monitor directory exists
if [ ! -d "web-monitor" ]; then
    echo -e "${RED}❌ web-monitor directory not found. Please run this script from the NoSleep-Ops root directory.${NC}"
    exit 1
fi

# Build the web monitor image
echo -e "${BLUE}🔨 Building web monitor Docker image...${NC}"
cd web-monitor
docker build -t nosleep-web-monitor .

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to build web monitor image${NC}"
    exit 1
fi

# Stop existing container if running
echo -e "${YELLOW}🛑 Stopping existing web monitor container...${NC}"
docker stop nosleep-web-monitor 2>/dev/null || true
docker rm nosleep-web-monitor 2>/dev/null || true

# Run the web monitor container
echo -e "${GREEN}🌐 Starting web monitor container...${NC}"
docker run -d \
    --name nosleep-web-monitor \
    --network nosleep-ops_default \
    -p 5000:5000 \
    --privileged \
    -v /var/log:/var/log:ro \
    -v $(pwd):/app/data \
    nosleep-web-monitor

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Web monitor started successfully!${NC}"
    echo -e "${BLUE}🌐 Access the dashboard at: http://localhost:5000${NC}"
    echo -e "${YELLOW}📊 The monitor will automatically detect attacks from your NoSleep-Ops lab${NC}"
    echo ""
    echo -e "${BLUE}📋 Container Status:${NC}"
    docker ps | grep nosleep-web-monitor
    echo ""
    echo -e "${YELLOW}💡 To view logs: docker logs -f nosleep-web-monitor${NC}"
    echo -e "${YELLOW}🛑 To stop: docker stop nosleep-web-monitor${NC}"
else
    echo -e "${RED}❌ Failed to start web monitor container${NC}"
    exit 1
fi

cd ..
echo -e "${GREEN}🎯 NoSleep-Ops Web Attack Monitor is now running!${NC}" 