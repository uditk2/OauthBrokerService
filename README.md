# OAuth Broker Service
This project sets up KeyCloak as an OAuth broker for Google authentication. It includes scripts to configure KeyCloak and a dummy application to test the OAuth flow.

## Prerequisites
    - Docker and Docker Compose
    - Python 3.8+
    - Google OAuth credentials (Client ID and Client Secret)

## Setup
 1. Clone this repository
 2. Copy `.env.example` to `.env` and fill in your Google OAuth credentials
 3. Start KeyCloak:
 ```
     docker-compose up -d
 ```
 4. Install Python dependencies:
 ```
     pip install -r requirements.txt
 ```
 5. Set up the KeyCloak realm and Google identity provider:
 ```
 python scripts/setup_realm.py
 ```

## Testing the OAuth Flow
 1. Register a test client in KeyCloak:
 ```
     python scripts/keycloak_admin.py register-client --name test-client
 ```
 2. Start the dummy application:
 ```
 cd dummy_app
 python main.py
 ```
 3. Open your browser and navigate to `http://localhost:8090`
 4. Click the "Login with Google" button to test the OAuth flow

## Project Structure
 - `docker-compose.yml`: Docker configuration for KeyCloak
 - `.env`: Environment variables for configuration
 - `scripts/`: Scripts for KeyCloak administration
 - `dummy_app/`: FastAPI application for testing the OAuth flow