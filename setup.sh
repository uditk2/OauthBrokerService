#!/bin/bash
set -e

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "Please edit .env file with your Google OAuth credentials"
    exit 1
fi

# Start KeyCloak
echo "Starting KeyCloak..."
docker-compose up -d

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