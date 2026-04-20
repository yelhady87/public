# OAuth Client Registration App

A simple web app for registering OAuth/OIDC clients on an OAuth server. Fill in your tenant, server URL, and admin token — the app calls the server's client registration API and saves the result locally.

## What it does

- Registers a new OAuth client via your server's admin API
- Displays the returned `client_id` and `client_secret`
- Persists all registered clients to `clients.json` for future retrieval
- Lists previously registered clients with a detail view

## Running with Docker

### Local development (hot reload)

```bash
cd oauth_clients
docker compose -f docker-compose.dev.yml up --build
```

Source code is bind-mounted, so changes are reflected immediately without rebuilding.

### Production

```bash
cd oauth_clients
docker compose up --build -d
```

Registered clients are persisted in a named Docker volume (`clients_data`). To inspect or back up the data:

```bash
docker compose cp app:/app/data/clients.json ./clients.json
```

---

## Local setup (without Docker)

### 1. Create and activate a virtual environment

```bash
cd oauth_clients
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the app

```bash
uvicorn main:app --reload
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

## Usage

Fill in the registration form with:

| Field | Description |
|-------|-------------|
| **Tenant Name** | The tenant/realm on your OAuth server |
| **OAuth Server Base URL** | Base URL of your OAuth server (e.g. `https://auth.example.com`) |
| **Admin PAT** | Personal Access Token with client-management permissions |
| **Client Name** | Display name for the new OAuth client |
| **Callback URLs** | One redirect URI per line |
| **Grant Types** | Select one or more: `authorization_code`, `client_credentials`, `refresh_token` |

On success, the `client_id` and `client_secret` are shown — copy them before navigating away. All registered clients are saved to `clients.json` and viewable in the list below the form.

## Configuration

The app calls `POST {base_url}/{tenant}/clients` with a `Bearer` token. If your server uses a different URL pattern, update the `endpoint` line in `main.py`:

```python
endpoint = f"{base}/{payload.tenant}/clients"
```

## Notes

- The Admin PAT is stored in **plaintext** in `clients.json` alongside the client credentials. Do not commit this file or expose it to untrusted parties.
- `clients.json` is created automatically on first registration.
