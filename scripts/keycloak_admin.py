#!/usr/bin/env python3
"""
Script for KeyCloak administration tasks like registering clients.
"""
import os
import sys
import json
import argparse
import uuid
from dotenv import load_dotenv
from keycloak import KeycloakAdmin

# Load environment variables
load_dotenv()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
KEYCLOAK_ADMIN = os.getenv("KEYCLOAK_ADMIN")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
DUMMY_APP_REDIRECT_URI = os.getenv("DUMMY_APP_REDIRECT_URI")


def connect_to_keycloak():
    """Connect to KeyCloak admin API"""
    try:
        # First try to connect to master realm to get token
        print(f"Connecting to KeyCloak at {KEYCLOAK_URL}")
        print(f"Using admin username: {KEYCLOAK_ADMIN}")
        
        # Check if required variables are set
        if not KEYCLOAK_URL or not KEYCLOAK_ADMIN or not KEYCLOAK_ADMIN_PASSWORD:
            print("ERROR: Missing required KeyCloak connection variables in environment")
            print(f"KEYCLOAK_URL: {'Set' if KEYCLOAK_URL else 'Missing'}")
            print(f"KEYCLOAK_ADMIN: {'Set' if KEYCLOAK_ADMIN else 'Missing'}")
            print(f"KEYCLOAK_ADMIN_PASSWORD: {'Set' if KEYCLOAK_ADMIN_PASSWORD else 'Missing'}")
            sys.exit(1)
            
        # First connect to master realm
        keycloak_admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username=KEYCLOAK_ADMIN,
            password=KEYCLOAK_ADMIN_PASSWORD,
            realm_name="master",  # Always connect to master realm first
            verify=False  # Disable SSL verification for local development
        )
        
        # Then switch to the specified realm if needed
        if KEYCLOAK_REALM and KEYCLOAK_REALM != "master":
            keycloak_admin.realm_name = KEYCLOAK_REALM
            print(f"Successfully connected to KeyCloak and switched to realm: {KEYCLOAK_REALM}")
        else:
            print("Successfully connected to KeyCloak master realm")
            
        return keycloak_admin
    except Exception as e:
        print(f"Failed to connect to KeyCloak admin API: {e}")
        print("Please check your credentials and ensure KeyCloak is running.")
        sys.exit(1)


def register_client(keycloak_admin, client_name, redirect_uris=None):
    """Register a new client in KeyCloak"""
    if redirect_uris is None:
        redirect_uris = [DUMMY_APP_REDIRECT_URI]
    client_id = f"{client_name}-{uuid.uuid4().hex[:8]}"
    client_representation = {
        "clientId": client_id,
        "name": client_name,
        "enabled": True,
        "publicClient": False,
        "redirectUris": redirect_uris,
        "webOrigins": ["+"],
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": False,
        "fullScopeAllowed": True,
        "protocol": "openid-connect"
    }
    try:
        client_id_created = keycloak_admin.create_client(client_representation)
        print(f"Client created with ID: {client_id_created}")
        client_secret = keycloak_admin.get_client_secrets(client_id_created)
        print(f"Client secret: {client_secret['value']}")
        client_info = {
            "client_id": client_id,
            "client_secret": client_secret['value'],
            "keycloak_url": KEYCLOAK_URL,
            "realm": KEYCLOAK_REALM,
            "redirect_uris": redirect_uris
        }
        with open(f"{client_name}_credentials.json", "w") as f:
            json.dump(client_info, f, indent=2)
        print(f"Client credentials saved to {client_name}_credentials.json")
        return client_info
    except Exception as e:
        print(f"Error creating client: {e}")
        sys.exit(1)


def list_clients(keycloak_admin):
    """List all clients in the realm"""
    try:
        clients = keycloak_admin.get_clients()
        print("Clients in realm:")
        for client in clients:
            print(f"  - {client['clientId']} (ID: {client['id']})")
    except Exception as e:
        print(f"Error listing clients: {e}")
        sys.exit(1)


def main():
    """Main function to parse arguments and execute commands"""
    parser = argparse.ArgumentParser(description="KeyCloak administration tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    register_parser = subparsers.add_parser("register-client", help="Register a new client")
    register_parser.add_argument("--name", required=True, help="Client name")
    register_parser.add_argument("--redirect-uri", action="append", help="Redirect URI (can be specified multiple times)")
    subparsers.add_parser("list-clients", help="List all clients in the realm")
    args = parser.parse_args()
    required_vars = ["KEYCLOAK_URL", "KEYCLOAK_ADMIN", "KEYCLOAK_ADMIN_PASSWORD", "KEYCLOAK_REALM"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these variables in your .env file.")
        sys.exit(1)
    keycloak_admin = connect_to_keycloak()
    if args.command == "register-client":
        redirect_uris = args.redirect_uri if args.redirect_uri else None
        register_client(keycloak_admin, args.name, redirect_uris)
    elif args.command == "list-clients":
        list_clients(keycloak_admin)
    else:
        parser.print_help()


def main_wrapper():
    main()


if __name__ == "__main__":
    main_wrapper()