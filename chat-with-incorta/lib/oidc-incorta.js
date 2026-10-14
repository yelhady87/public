const axios = require('axios');
const { Issuer } = require('openid-client');

const { logAccessToken } = require('./log-tokens');

/**
 * Resolve the Incorta tenant (project) name used in REST API paths.
 *
 * Prefers INCORTA_TENANT. When that is unset it falls back to the last path
 * segment of INCORTA_OIDC_ISSUER, because the OIDC issuer already names the
 * tenant: `http://localhost/incorta/oauth/demo_keycloak` implies tenant
 * `demo_keycloak`. The fallback keeps existing .env files working; the explicit
 * variable is what you need when the API should hit a different tenant than the
 * one that issued the token, which happens when tokens come from a parent tenant.
 *
 * The value is interpolated into a URL path, so it is restricted to a plain
 * name. Without that check a value like `../admin` or `demo?x=1` would
 * silently redirect the API call somewhere else.
 */
function resolveTenant() {
  const candidate =
    (process.env.INCORTA_TENANT || '').trim() || tenantFromIssuer();

  if (!candidate) {
    throw new Error(
      'Incorta tenant is not configured. Set INCORTA_TENANT in .env, or make INCORTA_OIDC_ISSUER end with the tenant name (e.g. http://localhost/incorta/oauth/demo_keycloak)'
    );
  }

  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(candidate)) {
    throw new Error(
      `Invalid Incorta tenant "${candidate}". Use letters, digits, dot, underscore or hyphen only - no slashes, spaces or ".." - since it becomes part of the API URL path.`
    );
  }

  return candidate;
}

/**
 * Last non-empty path segment of INCORTA_OIDC_ISSUER, used as the tenant
 * fallback. Handles trailing slashes so `.../demo_sso/` still resolves.
 */
function tenantFromIssuer() {
  const issuer = (process.env.INCORTA_OIDC_ISSUER || '').trim();
  if (!issuer) return '';
  const segments = issuer.replace(/\/+$/, '').split('/');
  return segments[segments.length - 1] || '';
}

/**
 * Incorta OIDC client - uses Client Credentials flow to obtain an access token
 * for API calls. The authenticated user's email is passed as the `for_user` parameter.
 */
class IncortaOIDCClient {
  constructor() {
    this.issuerUrl = process.env.INCORTA_OIDC_ISSUER;
    this.clientId = process.env.INCORTA_CLIENT_ID;
    this.clientSecret = process.env.INCORTA_CLIENT_SECRET;
    this.client = null;
  }

  /**
   * Initialize the OIDC client by fetching Incorta's discovery document
   */
  async init() {
    if (!this.issuerUrl || !this.clientId || !this.clientSecret) {
      throw new Error(
        'Incorta configuration missing. Please set INCORTA_OIDC_ISSUER, INCORTA_CLIENT_ID, and INCORTA_CLIENT_SECRET in .env'
      );
    }

    const issuer = await Issuer.discover(this.issuerUrl);
    this.client = new issuer.Client({
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });

    console.log(`✓ Incorta OIDC client initialized (issuer: ${this.issuerUrl})`);
    return this.client;
  }

  /**
   * Obtain an access token via Client Credentials flow, scoped to a specific user.
   * @param {string} userEmail - the authenticated user's email, passed as `for_user`
   * @returns {Promise<{access_token: string, expires_in: number}>}
   */
  async getAccessToken(userEmail) {
    if (!userEmail) {
      throw new Error('userEmail (for_user) is required to obtain an Incorta access token');
    }

    const tokenEndpoint = this.client.issuer.metadata.token_endpoint;
    if (!tokenEndpoint) {
      throw new Error('Incorta discovery document did not advertise a token_endpoint');
    }

    // Incorta expects `for_user` alongside the standard client credentials params
    const body = new URLSearchParams();
    body.append('grant_type', 'client_credentials');
    body.append('scope', 'openid');
    body.append('client_id', this.clientId);
    body.append('client_secret', this.clientSecret);
    body.append('for_user', userEmail);

    // URL only: the credentials and for_user travel in the body, never logged
    console.log(`→ Incorta API request: POST ${tokenEndpoint}`);

    const response = await axios.post(tokenEndpoint, body.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      // Surface Incorta's own error payload instead of throwing a generic error
      validateStatus: () => true,
    });

    if (response.status < 200 || response.status >= 300) {
      const detail =
        response.data && typeof response.data === 'object'
          ? JSON.stringify(response.data)
          : String(response.data);
      throw new Error(
        `Incorta token request failed (${response.status} ${response.statusText}): ${detail}`
      );
    }

    const tokenData = response.data;

    if (!tokenData.access_token) {
      throw new Error('Incorta token response did not include an access_token');
    }

    // Logged as it arrives, not on every API call: the route caches this token
    // in the session, so repeat calls would otherwise log the same value over
    // and over.
    logAccessToken('Incorta', tokenData.access_token, {
      for_user: userEmail,
      expires_in: tokenData.expires_in,
    });

    return tokenData;
  }
}

/**
 * Build an Incorta REST API URL for the configured tenant.
 *
 * Equivalent to:
 * http://localhost/incorta/api/v2/<tenant>/schema/list
 */
function incortaApiUrl(pathSuffix) {
  const tenant = resolveTenant();
  const base = (process.env.INCORTA_BASE_URL || 'http://localhost').replace(
    /\/+$/,
    ''
  );
  return `${base}/incorta/api/v2/${tenant}${pathSuffix}`;
}

module.exports = { IncortaOIDCClient, resolveTenant, incortaApiUrl };
