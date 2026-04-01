#!/usr/bin/env python3
"""
One-time script to get a Gmail refresh token using your Google Cloud Client ID and Client Secret.
Run from the "Main Project" folder (parent of scripts/).

  py scripts/get_gmail_refresh_token.py

Prerequisites:
  1. Google Cloud Console: create OAuth 2.0 credentials (Web application).
  2. Add Authorized redirect URIs (APIs & Services → Credentials → your OAuth client):
     http://localhost:8080/
     http://localhost:8090/
     http://localhost:9090/
     http://localhost:8765/
     http://localhost:9999/
     (Script tries these ports in order if one is in use.)
  3. Put Client ID and Client Secret in .env: GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...

Output: prints GOOGLE_REFRESH_TOKEN=... and GOOGLE_SENDER_EMAIL=... to add to .env.

If you get "Error 400: redirect_uri_mismatch":
  - Add the exact redirect URI (e.g. http://localhost:8080/) under your OAuth client.
  - Use "Web application" type, not Desktop. Save and wait a minute, then run again.
"""
import os
import sys

# Load .env from parent directory (Main Project)
_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(_parent, ".env"))
except ImportError:
    pass

CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
# Must match exactly what you add in Google Cloud Console → Credentials → Authorized redirect URIs
REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8080/").strip() or "http://localhost:8080/"

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


def main():
    if not CLIENT_ID or not CLIENT_SECRET:
        print("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env or environment.")
        print("Get them from Google Cloud Console → APIs & Services → Credentials → Create OAuth 2.0 Client ID.")
        sys.exit(1)
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("Install: pip install google-auth-oauthlib")
        sys.exit(1)
    # Try ports in order; add these redirect URIs in Google Console: 8080, 8090, 9090, 8765, 9999
    ports_and_uris = [
        (8080, "http://localhost:8080/"),
        (8090, "http://localhost:8090/"),
        (9090, "http://localhost:9090/"),
        (8765, "http://localhost:8765/"),
        (9999, "http://localhost:9999/"),
    ]
    creds = None
    for try_port, try_uri in ports_and_uris:
        try:
            flow = InstalledAppFlow.from_client_config(
                {
                    "installed": {
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                        "redirect_uris": [try_uri, "http://localhost"],
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                },
                scopes=SCOPES,
                redirect_uri=try_uri,
            )
            creds = flow.run_local_server(port=try_port, prompt="consent")
            break
        except OSError as e:
            in_use = getattr(e, "winerror", None) == 10048 or "Address already in use" in str(e)
            if in_use:
                print(f"Port {try_port} in use, trying next...")
                continue
            raise
    if creds is None:
        print("All ports 8080, 8090, 9090, 8765, 9999 are in use. Close other apps or add one of these to Google Console and set GOOGLE_REDIRECT_URI in .env.")
        sys.exit(1)
    refresh_token = getattr(creds, "refresh_token", None)
    if not refresh_token:
        print("No refresh token in response. Ensure you completed consent and use prompt='consent'.")
        sys.exit(1)
    # Sender email: we don't get it from token; user must set the Gmail that authorized
    print("\nAdd these to your .env file:\n")
    print(f"GOOGLE_REFRESH_TOKEN={refresh_token}")
    print("GOOGLE_SENDER_EMAIL=your.gmail@gmail.com   # The Gmail address that just signed in")
    print()


if __name__ == "__main__":
    main()
