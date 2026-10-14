/**
 * Access token logging.
 *
 * Tokens are bearer credentials: anything holding one can call the API as that
 * user. Server logs tend to be far more widely readable than the app itself -
 * shipped to log aggregators, attached to bug reports, kept for months in CI
 * output - so full tokens are OFF by default and must be opted into with
 * LOG_ACCESS_TOKENS=true.
 *
 * By default a masked fingerprint is logged instead. That is enough to answer
 * the questions that come up while debugging ("did the token rotate?", "is the
 * cached token the one I think it is?", "same token as the last call?") without
 * handing out something usable.
 *
 * Turn on only for local debugging, and never in a deployed environment:
 *   LOG_ACCESS_TOKENS=true
 */

const TRUTHY = /^(1|true|yes|on)$/i;
let warned = false;

/**
 * Is full token logging enabled? Read at call time so tests can toggle it.
 */
function isTokenLoggingEnabled() {
  return TRUTHY.test(String(process.env.LOG_ACCESS_TOKENS || '').trim());
}

/**
 * Mask a token for safe logging: a short prefix and suffix plus the length.
 *
 * The prefix alone identifies a JWT's algorithm and header, which is the useful
 * part when comparing tokens; the length catches truncated or double-encoded
 * values. Deliberately not reversible and not usable as a credential.
 */
function maskToken(token) {
  const value = String(token);
  if (value.length <= 12) {
    // Too short to reveal any prefix/suffix pair without printing the whole thing
    return `[${value.length} chars, too short to mask]`;
  }
  return `${value.slice(0, 6)}...${value.slice(-4)} (${value.length} chars)`;
}

/**
 * Log an access token as it is received.
 *
 * @param {string} label - where the token came from, e.g. 'Incorta' or 'SSO'
 * @param {string} token - the access token
 * @param {object} [meta] - extra context (subject, expiry, for_user, ...)
 */
function logAccessToken(label, token, meta = {}) {
  if (!token) {
    return;
  }

  const details = Object.entries(meta)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');

  if (isTokenLoggingEnabled()) {
    const suffix = details ? ` ${details}` : '';
    console.log(`🔓 ${label} access token: ${token}${suffix}`);
    if (!warned) {
      warned = true;
      console.warn(
        '⚠ LOG_ACCESS_TOKENS is enabled - full access tokens are being written to the server log. Turn it off outside local debugging.'
      );
    }
    return;
  }

  const suffix = details ? ` ${details}` : '';
  console.log(`🔒 ${label} access token: ${maskToken(token)}${suffix} (set LOG_ACCESS_TOKENS=true to log it in full)`);
}

module.exports = { logAccessToken, maskToken, isTokenLoggingEnabled };
