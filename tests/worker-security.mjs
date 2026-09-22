import assert from 'node:assert/strict';
import worker from '../src/worker.js';

class MemoryKV {
  constructor({ pageSize = Infinity, breakPagination = false } = {}) {
    this.map = new Map();
    this.putCalls = [];
    // pageSize < Infinity exercises the cursor/pagination path; the default
    // single-page behaviour keeps the existing assertions unchanged.
    this.pageSize = pageSize;
    // Simulates a KV that reports more data but never hands back a cursor.
    this.breakPagination = breakPagination;
  }

  async get(key) {
    return this.map.has(key) ? this.map.get(key).value : null;
  }

  async put(key, value, options = {}) {
    this.map.set(key, { value, options });
    this.putCalls.push({ key, options });
  }

  async delete(key) {
    this.map.delete(key);
  }

  async list(options = {}) {
    if (Object.prototype.hasOwnProperty.call(options, 'cursor') && options.cursor === undefined) {
      throw new TypeError('cursor must not be undefined');
    }
    const prefix = options.prefix || '';
    const all = [...this.map.keys()].filter((key) => key.startsWith(prefix)).sort();
    const start = options.cursor ? Number(options.cursor) : 0;
    const page = all.slice(start, start + this.pageSize);
    const nextIndex = start + page.length;

    if (nextIndex < all.length) {
      if (this.breakPagination) {
        // list_complete:false with no cursor must not loop forever.
        return { keys: page.map((name) => ({ name })), list_complete: false };
      }
      return {
        keys: page.map((name) => ({ name })),
        list_complete: false,
        cursor: String(nextIndex),
      };
    }

    return { keys: page.map((name) => ({ name })), list_complete: true };
  }
}

const kv = new MemoryKV();
const env = {
  SUB_STORE: kv,
  SUB_ACCESS_TOKEN: 'subscription-master-secret-that-is-long-enough',
  SUB_ADMIN_TOKEN: 'admin-secret-that-is-different-and-long-enough',
  ASSETS: {
    fetch: async () => new Response('not found', { status: 404 }),
  },
};

const generateBody = {
  nodeLinks:
    'vless://00000000-0000-4000-8000-000000000001@origin.example.com:443?type=xhttp&encryption=none&security=tls&host=origin.example.com&sni=origin.example.com&path=%2Fxhttp&mode=packet-up&alpn=h2%2Chttp%2F1.1&fp=chrome&x_padding_bytes=100-1000&extra=%7B%22headers%22%3A%7B%22X-Test%22%3A%22yes%22%7D%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#demo',
  preferredIps: '104.16.1.2#CF-01',
  namePrefix: 'CF',
  keepOriginalHost: true,
};

async function request(path, options = {}) {
  return worker.fetch(
    new Request('https://worker.example.com' + path, options),
    env,
  );
}

let response = await request('/api/generate', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(generateBody),
});
assert.equal(response.status, 403, 'generate must require admin token');

response = await request('/api/generate', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'x-admin-token': env.SUB_ADMIN_TOKEN,
  },
  body: JSON.stringify(generateBody),
});
assert.equal(response.status, 200);
const generated = await response.json();
assert.equal(generated.ok, true);
assert.ok(generated.shortId);
assert.ok(generated.urls.clash.includes('/sub/'));
assert.ok(generated.urls.clash.includes('token='));

const subPut = kv.putCalls.find((call) => call.key === 'sub:' + generated.shortId);
assert.ok(subPut, 'subscription should be persisted');
assert.equal(
  Object.hasOwn(subPut.options, 'expirationTtl'),
  false,
  'new subscriptions must not have an automatic TTL',
);

const rawRecord = JSON.parse(await kv.get('sub:' + generated.shortId));
assert.equal(rawRecord.schemaVersion, 2);
assert.equal(rawRecord.status, 'active');
assert.ok(rawRecord.tokenNonce);
assert.equal(JSON.stringify(rawRecord).includes('subscription-master-secret'), false);

response = await worker.fetch(new Request(generated.urls.clash), env);
assert.equal(response.status, 200);
const clashText = await response.text();
assert.match(clashText, /proxies:/);
assert.match(clashText, /network: xhttp/);
assert.match(clashText, /xhttp-opts:/);
assert.match(clashText, /mode: "packet-up"/);
assert.match(clashText, /path: "\/xhttp"/);
assert.match(clashText, /host: "origin\.example\.com"/);
assert.match(clashText, /alpn: \["h2", "http\/1\.1"\]/);
assert.match(clashText, /client-fingerprint: "chrome"/);
assert.match(clashText, /x-padding-bytes: "100-1000"/);
assert.match(clashText, /"X-Test": "yes"/);

const badUrl = new URL(generated.urls.clash);
badUrl.searchParams.set('token', 'bad-token');
response = await worker.fetch(new Request(badUrl.toString()), env);
assert.equal(response.status, 403);

response = await request('/api/subscriptions', {
  headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
});
assert.equal(response.status, 200);
let listed = await response.json();
assert.equal(listed.subscriptions.length, 1);
assert.equal(listed.subscriptions[0].status, 'active');

response = await request(
  '/api/subscriptions/' + encodeURIComponent(generated.shortId) + '/revoke',
  {
    method: 'POST',
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  },
);
assert.equal(response.status, 200);

response = await worker.fetch(new Request(generated.urls.clash), env);
assert.equal(response.status, 410, 'revoked link must return Gone');

response = await request(
  '/api/subscriptions/' + encodeURIComponent(generated.shortId) + '/reissue',
  {
    method: 'POST',
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  },
);
assert.equal(response.status, 200);
const reissued = await response.json();
assert.notEqual(reissued.shortId, generated.shortId);
assert.ok(reissued.urls.clash.includes(reissued.shortId));

response = await worker.fetch(new Request(reissued.urls.clash), env);
assert.equal(response.status, 200, 'reissued link must work');

response = await request(
  '/api/subscriptions/' + encodeURIComponent(reissued.shortId),
  {
    method: 'DELETE',
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  },
);
assert.equal(response.status, 200);

response = await worker.fetch(new Request(reissued.urls.clash), env);
response = await worker.fetch(new Request(reissued.urls.clash), env);
assert.equal(response.status, 404, 'deleted subscription must disappear');

// --- KV binding misconfiguration -------------------------------------------------
// Regression cover for the "读取订阅列表失败。" report: an unbound SUB_STORE used
// to surface as an opaque 500 with the real cause buried in `detail`.

const brokenEnv = { ...env, SUB_STORE: undefined };

response = await worker.fetch(
  new Request('https://worker.example.com/api/subscriptions', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  brokenEnv,
);
assert.equal(response.status, 503, 'missing KV binding must be reported as 503');
let broken = await response.json();
assert.equal(broken.ok, false);
assert.equal(broken.code, 'KV_BINDING_MISSING');
assert.match(broken.error, /SUB_STORE/);

// A text/secret variable bound under the same name is not a KV namespace.
const wrongTypeEnv = { ...env, SUB_STORE: 'not-a-namespace' };
response = await worker.fetch(
  new Request('https://worker.example.com/api/subscriptions', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  wrongTypeEnv,
);
assert.equal(response.status, 503, 'non-namespace binding must be reported as 503');
broken = await response.json();
assert.equal(broken.code, 'KV_BINDING_INVALID');

// Every KV-backed endpoint must fail closed with a structured error.
for (const [label, path, options] of [
  ['generate', '/api/generate', { method: 'POST', body: '{}' }],
  ['sub', '/sub/abc123', {}],
  ['revoke', '/api/subscriptions/abc123/revoke', { method: 'POST' }],
  ['reissue', '/api/subscriptions/abc123/reissue', { method: 'POST' }],
  ['delete', '/api/subscriptions/abc123', { method: 'DELETE' }],
]) {
  response = await worker.fetch(
    new Request('https://worker.example.com' + path, {
      ...options,
      headers: {
        'content-type': 'application/json',
        'x-admin-token': env.SUB_ADMIN_TOKEN,
      },
    }),
    brokenEnv,
  );
  // All KV-backed endpoints must fail closed with the structured code; a 404
  // here would mean the request was answered without ever touching the binding.
  assert.equal(
    response.status,
    503,
    `${label} must report a structured failure without the KV binding (got ${response.status})`,
  );
  assert.equal(
    (await response.json()).code,
    'KV_BINDING_MISSING',
    `${label} must report the missing binding`,
  );
}

// The health endpoint must report each piece of the deployment.
response = await worker.fetch(
  new Request('https://worker.example.com/api/health', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  env,
);
assert.equal(response.status, 200, 'healthy deployment must pass self-check');
const health = await response.json();
assert.equal(health.ok, true);
assert.equal(health.checks.kvBinding, 'ok');
assert.equal(health.checks.kvReadWrite, 'ok');
assert.equal(health.checks.accessToken, 'ok');

response = await worker.fetch(
  new Request('https://worker.example.com/api/health', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  brokenEnv,
);
assert.equal(response.status, 503, 'health must fail without the KV binding');
const brokenHealth = await response.json();
assert.equal(brokenHealth.checks.kvBinding, 'missing');
assert.equal(brokenHealth.code, 'HEALTHCHECK_FAILED');
assert.match(brokenHealth.error, /kvBinding=missing/, 'error must name the failing check');

// A wrong-typed binding must be distinguishable from a missing one.
response = await worker.fetch(
  new Request('https://worker.example.com/api/health', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  wrongTypeEnv,
);
assert.equal(response.status, 503);
assert.equal((await response.json()).checks.kvBinding, 'invalid-type');

response = await worker.fetch(new Request('https://worker.example.com/api/health'), env);
assert.equal(response.status, 403, 'health must require the admin token');

// A missing ASSETS binding breaks every static asset, so it must fail the check.
response = await worker.fetch(
  new Request('https://worker.example.com/api/health', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  { ...env, ASSETS: undefined },
);
assert.equal(response.status, 503);
assert.equal((await response.json()).checks.assetsBinding, 'missing');

// A missing SUB_ACCESS_TOKEN must be reported and must fail the check.
response = await worker.fetch(
  new Request('https://worker.example.com/api/health', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  { ...env, SUB_ACCESS_TOKEN: '' },
);
assert.equal(response.status, 503);
const noTokenHealth = await response.json();
assert.equal(noTokenHealth.checks.accessToken, 'missing');
assert.match(noTokenHealth.error, /accessToken=missing/);

// The probe key lives outside the 'sub:' prefix and must be cleaned up, so it
// can never be read back or listed as a subscription.
assert.equal(await kv.get('__healthcheck__'), null, 'health probe key must be deleted');

response = await request('/api/subscriptions', {
  headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
});
listed = await response.json();
assert.equal(listed.truncated, false);
assert.equal(
  listed.subscriptions.some((item) => item.id === '__healthcheck__'),
  false,
  'probe key must not appear as a subscription',
);

// --- KV pagination ---------------------------------------------------------------

// Keys are listed across multiple pages, so nothing may be dropped.
const pagedKv = new MemoryKV({ pageSize: 1 });
const pagedEnv = { ...env, SUB_STORE: pagedKv };
await pagedKv.put('sub:p1', JSON.stringify({ schemaVersion: 2, status: 'active', createdAt: 'a' }));
await pagedKv.put('sub:p2', JSON.stringify({ schemaVersion: 2, status: 'active', createdAt: 'b' }));
await pagedKv.put('sub:p3', JSON.stringify({ schemaVersion: 2, status: 'active', createdAt: 'c' }));
await pagedKv.put('dedup:zzz', 'sub:p1');

response = await worker.fetch(
  new Request('https://worker.example.com/api/subscriptions', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  pagedEnv,
);
assert.equal(response.status, 200);
listed = await response.json();
assert.equal(listed.subscriptions.length, 3, 'pagination must return every subscription');
assert.deepEqual(
  listed.subscriptions.map((item) => item.id).sort(),
  ['p1', 'p2', 'p3'],
);
assert.equal(listed.truncated, false);

// A paginated response with no cursor must be flagged, not silently truncated.
const brokenPagingKv = new MemoryKV({ pageSize: 1, breakPagination: true });
const brokenPagingEnv = { ...env, SUB_STORE: brokenPagingKv };
await brokenPagingKv.put('sub:x1', JSON.stringify({ schemaVersion: 2, status: 'active', createdAt: 'a' }));
await brokenPagingKv.put('sub:x2', JSON.stringify({ schemaVersion: 2, status: 'active', createdAt: 'b' }));

response = await worker.fetch(
  new Request('https://worker.example.com/api/subscriptions', {
    headers: { 'x-admin-token': env.SUB_ADMIN_TOKEN },
  }),
  brokenPagingEnv,
);
assert.equal(response.status, 200);
listed = await response.json();
assert.equal(listed.truncated, true, 'stalled pagination must be reported as truncated');
assert.equal(listed.subscriptions.length, 1);

console.log('worker security test passed');
