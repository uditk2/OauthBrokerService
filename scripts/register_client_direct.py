from dotenv import load_dotenv
load_dotenv()
import os
import requests
import uuid
import json
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
KEYCLOAK_ADMIN = os.getenv("KEYCLOAK_ADMIN")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
DUMMY_APP_REDIRECT_URI = os.getenv("DUMMY_APP_REDIRECT_URI")

# Print environment values
print(f"KEYCLOAK_URL: {KEYCLOAK_URL}")
print(f"KEYCLOAK_ADMIN: {KEYCLOAK_ADMIN}")
print(f"KEYCLOAK_REALM: {KEYCLOAK_REALM}")
print(f"DUMMY_APP_REDIRECT_URI: {DUMMY_APP_REDIRECT_URI}")
# Not printing password for security reasons

def register_client_direct(client_name, redirect_uris=None):
    """Register a client using direct REST API calls"""
    if redirect_uris is None:
        redirect_uris = [DUMMY_APP_REDIRECT_URI]
    
    # Get admin token
    token_url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    token_data = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": KEYCLOAK_ADMIN,
        "password": KEYCLOAK_ADMIN_PASSWORD
    }
    token_response = requests.post(token_url, data=token_data)
    token_response.raise_for_status()
    access_token = token_response.json()["access_token"]
    
    # Create client
    client_id = f"{client_name}-{uuid.uuid4().hex[:8]}"
    client_representation = {
        "clientId": client_id,
        "name": client_name,
        "enabled": True,
        "publicClient": False,
        "redirectUris": redirect_uris,
        "webOrigins": ["+"],
        "standardFlowEnabled": True,
        "serviceAccountsEnabled": True,
        "protocol": "openid-connect"
    }
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    client_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients"
    response = requests.post(client_url, json=client_representation, headers=headers)
    response.raise_for_status()
    
    # Get client ID from Location header
    location = response.headers.get("Location", "")
    client_id_created = location.split("/")[-1]
    
    # Get client secret
    client_secret_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id_created}/client-secret"
    secret_response = requests.get(client_secret_url, headers=headers)
    secret_response.raise_for_status()
    client_secret = secret_response.json()["value"]
    
    # Save credentials
    client_info = {
        "client_id": client_id,
        "client_secret": client_secret,
        "keycloak_url": KEYCLOAK_URL,
        "realm": KEYCLOAK_REALM,
        "redirect_uris": redirect_uris
    }
    with open(f"{client_name}_credentials.json", "w") as f:
        json.dump(client_info, f, indent=2)
    
    print(f"Client credentials saved to {client_name}_credentials.json")
    return client_info


def main():
    """Main function to register a client"""
    required_vars = [
        "KEYCLOAK_URL", "KEYCLOAK_ADMIN", "KEYCLOAK_ADMIN_PASSWORD", 
        "KEYCLOAK_REALM", "DUMMY_APP_REDIRECT_URI"
    ]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these variables in your .env file.")
        return
    
    client_name = "dummy-app"
    register_client_direct(client_name)
    
if __name__ == "__main__":
    main()