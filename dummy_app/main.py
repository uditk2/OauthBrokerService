#!/usr/bin/env python3
"""
Dummy FastAPI application to test the KeyCloak OAuth flow.
"""
import os
import json
import httpx
from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080/auth")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
DUMMY_APP_PORT = int(os.getenv("DUMMY_APP_PORT", "8090"))
DUMMY_APP_HOST = os.getenv("DUMMY_APP_HOST", "localhost")
DUMMY_APP_REDIRECT_URI = os.getenv("DUMMY_APP_REDIRECT_URI", f"http://{DUMMY_APP_HOST}:{DUMMY_APP_PORT}/auth/callback")

# Path to the templates directory
current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, "templates")

# Create the templates directory if it doesn't exist
os.makedirs(templates_dir, exist_ok=True)

app = FastAPI(title="OAuth Test App")

# Add session middleware with a random secret key
app.add_middleware(SessionMiddleware, secret_key=os.urandom(24).hex())

# Set up templates
templates = Jinja2Templates(directory=templates_dir)

# Load client credentials from file
try:
    with open("test-client_credentials.json", "r") as f:
        credentials = json.load(f)
        CLIENT_ID = credentials["client_id"]
        CLIENT_SECRET = credentials["client_secret"]
except (FileNotFoundError, json.JSONDecodeError, KeyError):
    print("Warning: Client credentials not found. Please register a client first.")
    print("Run: python scripts/keycloak_admin.py register-client --name test-client")
    CLIENT_ID = None
    CLIENT_SECRET = None

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the main page with login status"""
    user = request.session.get("user")
    error = request.session.get("error")
    if error:
        request.session.pop("error")
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "user_json": json.dumps(user, indent=2) if user else None,
            "error": error,
            "keycloak_url": KEYCLOAK_URL,
            "realm": KEYCLOAK_REALM
        }
    )

@app.get("/login")
async def login(request: Request):
    """Redirect to Keycloak login page"""
    if not CLIENT_ID:
        request.session["error"] = "Client credentials not found. Please register a client first."
        return RedirectResponse(
            url="/",
            status_code=status.HTTP_303_SEE_OTHER
        )
    
    auth_url = (
        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={DUMMY_APP_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid+email+profile"
        f"&kc_idp_hint=google"  # This parameter tells Keycloak to use Google identity provider
    )
    return RedirectResponse(url=auth_url)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None, error: str = None):
    """Handle the OAuth callback from Keycloak"""
    if error:
        request.session["error"] = f"Authentication error: {error}"
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    
    if not code:
        request.session["error"] = "No authorization code received"
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    
    token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    try:
        async with httpx.AsyncClient() as client:
            # Exchange authorization code for tokens
            token_response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": DUMMY_APP_REDIRECT_URI
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            token_data = token_response.json()
            
            if "error" in token_data:
                request.session["error"] = f"Token error: {token_data.get('error_description', token_data['error'])}"
                return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
            
            # Get user info using the access token
            userinfo_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
            userinfo_response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {token_data['access_token']}"}
            )
            user_data = userinfo_response.json()
            
            # Store user data and tokens in session
            request.session["user"] = user_data
            request.session["tokens"] = {
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token"),
                "id_token": token_data.get("id_token")
            }
            
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        request.session["error"] = f"Error during authentication: {str(e)}"
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout(request: Request):
    """Log out the user by clearing session and redirecting to Keycloak logout"""
    # Get tokens before clearing session
    tokens = request.session.get("tokens", {})
    id_token = tokens.get("id_token")
    
    # Clear session data
    request.session.clear()
    
    # If we have an ID token, perform proper OIDC logout via Keycloak
    if id_token and CLIENT_ID:
        logout_url = (
            f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
            f"?client_id={CLIENT_ID}"
            f"&post_logout_redirect_uri={DUMMY_APP_REDIRECT_URI.rsplit('/', 1)[0]}"
        )
        if id_token:
            logout_url += f"&id_token_hint={id_token}"
        
        return RedirectResponse(url=logout_url, status_code=status.HTTP_303_SEE_OTHER)
    
    # Simple local logout if we don't have tokens
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

if __name__ == "__main__":
    import uvicorn
    print(f"Starting OAuth test app on http://{DUMMY_APP_HOST}:{DUMMY_APP_PORT}")
    print(f"Using Keycloak at {KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}")
    print(f"Templates directory: {templates_dir}")
    uvicorn.run(app, host=DUMMY_APP_HOST, port=DUMMY_APP_PORT)