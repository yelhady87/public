/**
 * Values shared by more than one module, derived from the environment in a
 * single place so they cannot drift apart.
 *
 * The redirect URI in particular is load-bearing: it is what gets registered in
 * FusionAuth, and the launcher must recognise it when it shows up among an
 * application's authorized redirect URIs (see lib/fusionauth-api.js).
 */

function appBaseUrl() {
  return (
    process.env.APP_BASE_URL ||
    `http://localhost:${process.env.APP_PORT || 3000}`
  );
}

/**
 * The launcher's own OIDC callback. Registered in FusionAuth as an authorized
 * redirect URI for the launcher application.
 */
function launcherRedirectUri() {
  return `${appBaseUrl()}/callback`;
}

module.exports = { appBaseUrl, launcherRedirectUri };
