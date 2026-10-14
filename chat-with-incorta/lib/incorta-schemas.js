const axios = require('axios');

const { incortaApiUrl } = require('./oidc-incorta');

/**
 * Call Incorta's schema list API for the configured tenant.
 *
 * The tenant (project) comes from INCORTA_TENANT, falling back to the last
 * segment of INCORTA_OIDC_ISSUER. With INCORTA_TENANT=demo_sso this is:
 *
 * curl -X 'POST' \
 *   'http://localhost/incorta/api/v2/demo_sso/schema/list?schemaType=ALL' \
 *   -H 'accept: application/json' \
 *   -H 'Content-Type: application/json' \
 *   -d '{"limit": 0, "offset": 0, "sortBy": "NAME_ASC"}'
 *
 * Never throws on a 4xx/5xx, so the caller can surface Incorta's own error
 * body. Transport failures (connection refused) do throw.
 *
 * @param {object} options
 * @param {string} options.accessToken - Incorta access token
 * @returns {Promise<{status: number, data: any, traceId: string|undefined, url: string}>}
 */
async function listSchemas({ accessToken }) {
  const url = incortaApiUrl('/schema/list?schemaType=ALL');
  console.log(`→ Incorta API request: POST ${url}`);

  const response = await axios.post(
    url,
    { limit: 0, offset: 0, sortBy: 'NAME_ASC' },
    {
      headers: {
        accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      validateStatus: () => true,
    }
  );

  return {
    status: response.status,
    data: response.data,
    // Incorta stamps every response, 4xx/5xx included, with a `trace-id`: the
    // handle to quote to Incorta support.
    traceId: response.headers['trace-id'],
    url,
  };
}

module.exports = { listSchemas };
