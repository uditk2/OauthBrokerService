#!/bin/bash
set -e

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "Please edit .env file with your Google OAuth credentials"
    exit 1
fi
echo "Shutting down any existing KeyCloak containers..."

docker compose -f docker-compose-prod.yml --env-file .env down

echo "Cleaning up system."
docker system prune -f
# Start KeyCloak
echo "Starting KeyCloak..."
docker compose -f docker-compose-prod.yml --env-file .env up --build -d

# Create virtual environment
echo "Creating Python virtual environment..."
# Try to create virtual environment
if ! python3 -m venv venv 2>/dev/null; then
    echo "Failed to create virtual environment. Python venv package may be missing."
    echo "Installing python3-venv package..."
    sudo apt install python3-venv -y
    
    # Try creating the venv again
    if ! python3 -m venv venv; then
        echo "Failed to create virtual environment even after installing python3-venv"
        exit 1
    fi
fi

# Activate the virtual environment
source venv/bin/activate
# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# KeyCloak readiness is checked in the Python script
echo "Setting up KeyCloak realm..."
python scripts/setup_realm.py

# Register a test client
echo "Registering a test client..."
python scripts/keycloak_admin.py register-client --name test-client

echo "Setup complete!"
echo "You can now run the dummy app with: cd dummy_app && python main.py"