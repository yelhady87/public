# Dynamic OIDC Demo Client

A self-registering OAuth/OIDC client. It fetches the server's OpenID Connect
discovery document, dynamically registers itself via the advertised
`registration_endpoint` (RFC 7591), and then runs the authorization-code flow
with PKCE.

## What it does

1. **Discover** — fetches the OIDC discovery document and extracts the
   registration, authorization, token, and JWKS endpoints.
2. **Register** — POSTs its client metadata to the discovery-provided
   `registration_endpoint` and stores the returned `client_id`,
   `client_secret`, and registration tokens in `data/registration.json`.
3. **Authenticate** — `/login` builds the authorization URL with PKCE
   (`S256`); `/callback` exchanges the code at the token endpoint and the ID
   token is signature-verified against the provider JWKS.
4. **Refresh** — exchanges a stored refresh token at the token endpoint.

## Run it

```bash
cd oauth_clients/dynamic_client
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --port 8100
```

Open [http://localhost:8100](http://localhost:8100).

### Docker

```bash
cd oauth_clients/dynamic_client
docker compose up --build
```

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `OIDC_DISCOVERY_URL` | `http://host.docker.internal/incorta/oauth/demo/.well-known/openid-configuration` | Discovery document used to find the registration endpoint |
| `PUBLIC_BASE_URL` | `http://localhost:8100` | Public URL of this app; the callback is `<PUBLIC_BASE_URL>/callback` and must be listed as an allowed redirect URI |
| `CLIENT_NAME` | `Dynamic OIDC Demo Client` | `client_name` sent during registration |
| `CLIENT_SCOPES` | `openid profile email` | Scopes requested during registration and login |
| `INITIAL_ACCESS_TOKEN` | *(empty)* | Optional bearer token sent to the registration endpoint |

The registration record is written to `data/registration.json` and reused on
restart, so the client is only registered once.

The endpoint URLs advertised in the discovery document (authorization, token,
registration, JWKS, etc.) are rewritten to use the same host as
`OIDC_DISCOVERY_URL`. That way a provider advertising `localhost` endpoints
can still be reached when the client runs in Docker
(`host.docker.internal`), and local runs can keep `localhost` by pointing
`OIDC_DISCOVERY_URL` at it.

## Notes

- `data/registration.json` contains the plaintext `client_secret` and the
  registration access token. Do not commit or expose this file.
- The ID token is verified against the JWKS advertised in the discovery
  document. If verification fails, the claims are decoded unverified so the
  demo stays usable, and a warning is logged.
