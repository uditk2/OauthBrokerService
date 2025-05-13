#!/usr/bin/env python3
"""
Script to set up a KeyCloak realm with Google as an identity provider.
"""
import os
import sys
import time
from dotenv import load_dotenv
from keycloak import KeycloakAdmin

# Load environment variables
load_dotenv()

# KeyCloak configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
KEYCLOAK_ADMIN = os.getenv("KEYCLOAK_ADMIN")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

def wait_for_keycloak():
    """Wait for KeyCloak to be ready"""
    import httpx
    import urllib.parse
    
    max_retries = 30
    retry_interval = 5
    
    # Make sure the URL doesn't have trailing slash
    base_url = KEYCLOAK_URL.rstrip("/")
    print(f"Base Keycloak URL: {base_url}")
    
    # List of possible health check endpoints to try
    health_endpoints = [
        "",  # Base URL itself
        "/",  # Root path
        "/auth",  # Legacy base path
        "/auth/",  # Legacy base path with slash
        "/health",  # Health endpoint
        "/health/ready",  # Health ready endpoint
        "/auth/health/ready",  # Legacy health ready endpoint
        "/realms/master",  # Master realm endpoint
        "/auth/realms/master"  # Legacy master realm endpoint
    ]
    
    for i in range(max_retries):
        for endpoint in health_endpoints:
            try:
                url = urllib.parse.urljoin(base_url, endpoint)
                print(f"Trying to connect to {url}")
                # Disable SSL verification for local development
                response = httpx.get(url, timeout=5, verify=False)
                print(f"Response from {url}: status_code={response.status_code}")
                if response.status_code in [200, 301, 302, 303, 307, 308]:  # Accept any successful or redirect status
                    print(f"KeyCloak is ready! Successfully connected to {url}")
                    return True
            except httpx.RequestError as e:
                print(f"Request to {url} failed: {e}")
                continue
        
        print(f"Waiting for KeyCloak to be ready... ({i+1}/{max_retries})")
        time.sleep(retry_interval)
    
    print("KeyCloak is not ready after maximum retries. Exiting.")
    return False

def create_realm(keycloak_admin):
    """Create a new realm if it doesn't exist"""
    realms = keycloak_admin.get_realms()
    if any(realm['realm'] == KEYCLOAK_REALM for realm in realms):
        print(f"Realm '{KEYCLOAK_REALM}' already exists.")
        return
    
    realm_representation = {
        "realm": KEYCLOAK_REALM,
        "enabled": True,
        "sslRequired": "external",
        "registrationAllowed": True,
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "resetPasswordAllowed": True,
        "editUsernameAllowed": False,
        "bruteForceProtected": True
    }
    keycloak_admin.create_realm(payload=realm_representation, skip_exists=True)
    print(f"Created realm '{KEYCLOAK_REALM}'")

def setup_google_identity_provider(keycloak_admin):
    """Set up Google as an identity provider"""
    keycloak_admin.realm_name = KEYCLOAK_REALM
    
    # Calculate the redirect URI that Keycloak will use for Google callbacks
    keycloak_base = KEYCLOAK_URL.rstrip("/")
    # Determine the correct format based on Keycloak version
    # For Keycloak ≥17, use modern format without "/auth"
    # For Keycloak <17, use legacy format with "/auth"
    has_auth_in_path = "/auth" in keycloak_base
    if has_auth_in_path:
        # Legacy Keycloak with /auth in the path
        redirect_uri = f"{keycloak_base}/realms/{KEYCLOAK_REALM}/broker/google/endpoint"
    else:
        # Modern Keycloak without /auth in the path
        redirect_uri = f"{keycloak_base}/realms/{KEYCLOAK_REALM}/broker/google/endpoint"
    
    print("\n=== IMPORTANT: GOOGLE OAUTH CONFIGURATION ===")
    print("Use this redirect URI in your Google OAuth client:")
    print(f"Redirect URI: {redirect_uri}")
    print("===================================================\n")
    
    try:
        # Check if Google provider already exists
        try:
            # Try modern method name first
            providers = keycloak_admin.get_idps()
        except AttributeError:
            # Fall back to traditional method name
            providers = keycloak_admin.get_identity_providers()
            
        if any(provider.get('alias') == 'google' for provider in providers):
            print("Google identity provider already exists.")
            return
    except Exception as e:
        print(f"Error checking identity providers: {e}")
        print("Will attempt to create Google provider anyway.")
    
    google_provider = {
        "alias": "google",
        "displayName": "Google",
        "providerId": "google",
        "enabled": True,
        "updateProfileFirstLoginMode": "on",
        "trustEmail": True,
        "storeToken": False,
        "addReadTokenRoleOnCreate": False,
        "authenticateByDefault": False,
        "linkOnly": False,
        "firstBrokerLoginFlowAlias": "first broker login",
        "config": {
            "clientId": GOOGLE_CLIENT_ID,
            "clientSecret": GOOGLE_CLIENT_SECRET,
            "useJwksUrl": True,
            "defaultScope": "openid email profile",
            "guiOrder": "1",
            # Add these important Google-specific settings
            "hostedDomain": "",  # Leave empty to allow any Google account
            "userIp": "false",
            "hibernateIdpPersistenceId": "",
            "backchannelSupported": "true"
        }
    }
    
    try:
        # Try creating the provider with proper error handling
        try:
            # Try modern method name first
            result = keycloak_admin.create_idp("google", google_provider)
        except (AttributeError, TypeError):
            # Fall back to traditional method name with different parameters
            result = keycloak_admin.create_identity_provider(provider_id="google", provider=google_provider)
            
        print("Google identity provider created successfully.")
    except Exception as e:
        print(f"Error creating Google identity provider: {e}")
        print("Detailed error information:", str(e))

def main():
    """Main function to set up KeyCloak realm and Google identity provider"""
    required_vars = [
        "KEYCLOAK_URL", "KEYCLOAK_ADMIN", "KEYCLOAK_ADMIN_PASSWORD", 
        "KEYCLOAK_REALM", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"
    ]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these variables in your .env file.")
        sys.exit(1)
    
    # Wait for KeyCloak to be ready
    if not wait_for_keycloak():
        sys.exit(1)
        
    try:
        # First connect to master realm
        print(f"Connecting to KeyCloak at {KEYCLOAK_URL}")
        print(f"Using admin username: {KEYCLOAK_ADMIN}")
        keycloak_admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username=KEYCLOAK_ADMIN,
            password=KEYCLOAK_ADMIN_PASSWORD,
            realm_name="master",  # Always connect to master realm first
            verify=False  # Disable SSL verification for local development
        )
        print("Successfully connected to KeyCloak admin API")
        
        # Create the realm if it doesn't exist
        create_realm(keycloak_admin)
        
        # After creating the realm, update the admin's realm_name
        keycloak_admin.realm_name = KEYCLOAK_REALM
        print(f"Switched to realm: {KEYCLOAK_REALM}")
        
        # Set up the Google identity provider
        setup_google_identity_provider(keycloak_admin)
        print("KeyCloak realm setup completed successfully!")
        
    except Exception as e:
        print(f"Failed to connect to KeyCloak admin API: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
