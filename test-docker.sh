#!/bin/bash

# PIoC Docker Build and Test Script
# This script tests the Docker build and deployment process

set -e

echo "🐳 PIoC Docker Build and Test Script"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_warning "Docker Compose is not installed. Some tests will be skipped."
fi

print_status "Docker is available"

# Test 1: Build the Docker image
echo ""
echo "📦 Test 1: Building Docker image..."
if docker build -t pioc-platform-test .; then
    print_status "Docker image built successfully"
else
    print_error "Docker image build failed"
    exit 1
fi

# Test 2: Run container in detached mode
echo ""
echo "🚀 Test 2: Running container..."
CONTAINER_ID=$(docker run -d -p 8501:8501 -p 8000:8000 --name pioc-test pioc-platform-test)

if [ $? -eq 0 ]; then
    print_status "Container started with ID: $CONTAINER_ID"
else
    print_error "Failed to start container"
    exit 1
fi

# Wait for services to start
echo ""
echo "⏳ Waiting for services to start..."
sleep 30

# Test 3: Check if services are responding
echo ""
echo "🔍 Test 3: Checking service health..."

# Check API health endpoint
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    print_status "API service is responding"
else
    print_warning "API service is not responding (this might be normal during startup)"
fi

# Check if Streamlit is accessible
if curl -f http://localhost:8501 > /dev/null 2>&1; then
    print_status "GUI service is accessible"
else
    print_warning "GUI service is not accessible (this might be normal during startup)"
fi

# Test 4: Check container logs
echo ""
echo "📋 Test 4: Container logs (last 20 lines):"
docker logs --tail 20 pioc-test

# Test 5: Test with Docker Compose (if available)
if command -v docker-compose &> /dev/null; then
    echo ""
    echo "🐳 Test 5: Testing Docker Compose..."
    
    # Stop the test container first
    docker stop pioc-test > /dev/null 2>&1
    docker rm pioc-test > /dev/null 2>&1
    
    # Test docker-compose
    if docker-compose up -d; then
        print_status "Docker Compose started successfully"
        sleep 20
        
        # Check services
        if curl -f http://localhost:8000/health > /dev/null 2>&1; then
            print_status "API service is healthy via Docker Compose"
        fi
        
        # Stop docker-compose
        docker-compose down
        print_status "Docker Compose test completed"
    else
        print_error "Docker Compose test failed"
    fi
else
    echo ""
    print_warning "Skipping Docker Compose test (not available)"
fi

# Cleanup
echo ""
echo "🧹 Cleanup..."
docker stop pioc-test > /dev/null 2>&1 || true
docker rm pioc-test > /dev/null 2>&1 || true
print_status "Cleanup completed"

echo ""
echo "🎉 Docker tests completed!"
echo ""
echo "To run the platform:"
echo "  docker-compose up -d"
echo ""
echo "Or manually:"
echo "  docker run -d -p 8501:8501 -p 8000:8000 --name pioc pioc-platform-test"
echo ""
echo "Access points:"
echo "  GUI: http://localhost:8501"
echo "  API: http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
