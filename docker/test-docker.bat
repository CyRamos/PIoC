@echo off
setlocal enabledelayedexpansion

REM PIoC Docker Build and Test Script for Windows
REM This script tests the Docker build and deployment process

echo 🐳 PIoC Docker Build and Test Script
echo ====================================

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Docker Compose is not installed. Some tests will be skipped.
)

echo ✅ Docker is available

REM Test 1: Build the Docker image
echo.
echo 📦 Test 1: Building Docker image...
docker build -t pioc-platform-test .
if errorlevel 1 (
    echo ❌ Docker image build failed
    pause
    exit /b 1
)
echo ✅ Docker image built successfully

REM Test 2: Run container in detached mode
echo.
echo 🚀 Test 2: Running container...
docker run -d -p 8501:8501 -p 8000:8000 --name pioc-test pioc-platform-test
if errorlevel 1 (
    echo ❌ Failed to start container
    pause
    exit /b 1
)
echo ✅ Container started successfully

REM Wait for services to start
echo.
echo ⏳ Waiting for services to start...
timeout /t 30 /nobreak >nul

REM Test 3: Check if services are responding
echo.
echo 🔍 Test 3: Checking service health...

REM Check API health endpoint
curl -f http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    echo ⚠️  API service is not responding (this might be normal during startup)
) else (
    echo ✅ API service is responding
)

REM Check if Streamlit is accessible
curl -f http://localhost:8501 >nul 2>&1
if errorlevel 1 (
    echo ⚠️  GUI service is not accessible (this might be normal during startup)
) else (
    echo ✅ GUI service is accessible
)

REM Test 4: Check container logs
echo.
echo 📋 Test 4: Container logs (last 20 lines):
docker logs --tail 20 pioc-test

REM Test 5: Test with Docker Compose (if available)
docker-compose --version >nul 2>&1
if not errorlevel 1 (
    echo.
    echo 🐳 Test 5: Testing Docker Compose...
    
    REM Stop the test container first
    docker stop pioc-test >nul 2>&1
    docker rm pioc-test >nul 2>&1
    
    REM Test docker-compose
    docker-compose up -d
    if errorlevel 1 (
        echo ❌ Docker Compose test failed
    ) else (
        echo ✅ Docker Compose started successfully
        timeout /t 20 /nobreak >nul
        
        REM Check services
        curl -f http://localhost:8000/health >nul 2>&1
        if not errorlevel 1 (
            echo ✅ API service is healthy via Docker Compose
        )
        
        REM Stop docker-compose
        docker-compose down
        echo ✅ Docker Compose test completed
    )
) else (
    echo.
    echo ⚠️  Skipping Docker Compose test (not available)
)

REM Cleanup
echo.
echo 🧹 Cleanup...
docker stop pioc-test >nul 2>&1
docker rm pioc-test >nul 2>&1
echo ✅ Cleanup completed

echo.
echo 🎉 Docker tests completed!
echo.
echo To run the platform:
echo   docker-compose up -d
echo.
echo Or manually:
echo   docker run -d -p 8501:8501 -p 8000:8000 --name pioc pioc-platform-test
echo.
echo Access points:
echo   GUI: http://localhost:8501
echo   API: http://localhost:8000
echo   API Docs: http://localhost:8000/docs
echo.
pause
