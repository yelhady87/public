const axios = require('axios');
const { launcherRedirectUri } = require('./config');

/**
 * Client for the FusionAuth *management* API - the half of the API that reads
 * which applications a user has been registered for.
 *
 * Two things about FusionAuth 1.62.1 drive the shape of this file, both verified
 * against a running instance:
 *
 *   1. There is no `/v2` segment in the path. The endpoints are
 *      `/api/user/{id}/applications` and `/api/application`. Requests to
 *      `/api/v2/...` return 404, and the string `/api/v2` does not appear in
 *      fusionauth-app-1.62.1.jar at all.
 *
 *   2. These endpoints do not accept an end user's access token. They require a
 *      FusionAuth API key, so the launcher holds one as a service credential.
 *      Because an API key is not itself bound to a tenant, the tenant has to be
 *      named explicitly via the X-FusionAuth-TenantId header or every call
 *      fails with [TenantIdRequired].
 */
class FusionAuthApiClient {
  constructor() {
    this.issuer = process.env.FUSION_AUTH_ISSUER;
    this.tenantId = process.env.FUSION_AUTH_TENANT_ID;
    this.apiKey = process.env.FUSION_AUTH_API_KEY;
    // The launcher is registered as an application too, but it is not something
    // a user should be able to "launch" into, so it is filtered out of results.
    this.selfClientId = process.env.FUSION_AUTH_CLIENT_ID;
  }

  /**
   * Origin of the management API. Defaults to the origin of the OIDC issuer,
   * which is right for a single-instance install; override with
   * FUSION_AUTH_API_URL when the API sits behind a different host.
   */
  apiBase() {
    if (process.env.FUSION_AUTH_API_URL) {
      return process.env.FUSION_AUTH_API_URL.replace(/\/+$/, '');
    }
    return new URL(this.issuer).origin;
  }

  headers() {
    const headers = {};
    if (this.apiKey) {
      headers.Authorization = this.apiKey;
    }
    if (this.tenantId) {
      headers['X-FusionAuth-TenantId'] = this.tenantId;
    }
    return headers;
  }

  assertConfigured() {
    if (!this.issuer) {
      throw new Error('FUSION_AUTH_ISSUER is not set');
    }
    if (!this.apiKey) {
      throw new Error(
        'FUSION_AUTH_API_KEY is not set. The management API needs an API key - ' +
          "a user's access token is not accepted. Create one in the FusionAuth admin UI."
      );
    }
  }

  /**
   * Surface FusionAuth's own error text instead of a bare axios message. Its
   * [TenantIdRequired] and [Invalid] bodies name the actual problem.
   */
  static describeError(err) {
    const data = err.response && err.response.data;
    if (data && Array.isArray(data.generalErrors) && data.generalErrors.length) {
      return data.generalErrors.map((e) => `${e.code} ${e.message}`).join('; ');
    }
    return err.message;
  }

  async request(config) {
    try {
      const response = await axios({
        ...config,
        baseURL: this.apiBase(),
        headers: { ...this.headers(), ...(config.headers || {}) },
        timeout: 10000,
      });
      return response.data;
    } catch (err) {
      throw new Error(
        `FusionAuth management API ${config.method.toUpperCase()} ${config.url} failed: ` +
          FusionAuthApiClient.describeError(err)
      );
    }
  }

  /**
   * A user's application registrations (applicationId + roles).
   */
  async getUserRegistrations(userId) {
    this.assertConfigured();
    const data = await this.request({
      method: 'GET',
      url: `/api/user/${encodeURIComponent(userId)}/applications`,
    });
    return (data && data.user) || {};
  }

  /**
   * Every application in the tenant.
   */
  async listApplications() {
    this.assertConfigured();
    const data = await this.request({ method: 'GET', url: '/api/application' });
    return (data && data.applications) || [];
  }

  /**
   * Choose which of an application's authorized redirect URIs to launch into.
   *
   * This cannot simply be "the first one". Two real cases from a 1.62.1 tenant
   * make the naive choice actively wrong:
   *
   *   - An application can list the LAUNCHER'S OWN /callback among its
   *     authorized URIs. Sending the browser there delivers the authorization
   *     code back to the launcher, which is not the application that asked for
   *     it, so it rejects the response. The user clicks a tile and gets a CSRF
   *     error instead of an app. Schema_Browser in a stock local install lists
   *     both `http://localhost:3000/callback` (the launcher's) and
   *     `http://localhost:3001/callback` (its own), and the launcher happens to
   *     run on 3000.
   *
   *   - FusionAuth-hosted UIs register a path-only URI such as `/admin/login`,
   *     which has to be resolved against the FusionAuth origin before it is
   *     usable as a redirect_uri.
   *
   * Returns an absolute URL, or null when nothing launchable is left.
   */
  pickRedirectUri(app) {
    const uris =
      (app.oauthConfiguration && app.oauthConfiguration.authorizedRedirectURLs) ||
      [];
    const mine = launcherRedirectUri().replace(/\/+$/, '');

    for (const uri of uris) {
      let absolute;
      try {
        // Relative URIs ("/admin/login") resolve against the FusionAuth origin.
        absolute = new URL(uri, `${this.apiBase()}/`).toString();
      } catch (err) {
        continue;
      }
      // Skip the launcher's own callback: a code landing there is never ours.
      if (absolute.replace(/\/+$/, '') === mine) continue;
      return absolute;
    }
    return null;
  }

  /**
   * The launchable apps for one user, as tile data.
   *
   * Filters, in order:
   *   - registration whose application no longer exists
   *   - inactive applications
   *   - applications with no redirect URI that is actually launchable (see
   *     pickRedirectUri)
   *   - this launcher itself
   *
   * Sorted by display name so the grid order is stable.
   */
  async listAppsForUser(userId) {
    const [user, applications] = await Promise.all([
      this.getUserRegistrations(userId),
      this.listApplications(),
    ]);

    const byId = new Map(applications.map((app) => [app.id, app]));
    const tiles = [];

    for (const registration of user.registrations || []) {
      const app = byId.get(registration.applicationId);
      if (!app) continue;
      if (app.active === false) continue;
      if (app.id === this.selfClientId) continue;

      const redirectUris =
        (app.oauthConfiguration && app.oauthConfiguration.authorizedRedirectURLs) || [];

      // An application may list only the launcher's own callback, which leaves
      // nothing to launch into - treat it as not launchable.
      const redirectUri = this.pickRedirectUri(app);
      if (!redirectUri) continue;
      if (!redirectUris.length) continue;

      tiles.push({
        applicationId: app.id,
        name: app.name,
        // `roles` comes back as an array of role name strings.
        roles: Array.isArray(registration.roles) ? registration.roles.slice() : [],
        redirectUri,
      });
    }

    tiles.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    return tiles;
  }

  /**
   * Look up one assigned app. Used by /launch/:appId so that a user can only
   * ever be redirected into an application they are actually registered for.
   */
  async findAppForUser(userId, applicationId) {
    const tiles = await this.listAppsForUser(userId);
    return tiles.find((tile) => tile.applicationId === applicationId) || null;
  }
}

module.exports = { FusionAuthApiClient };
