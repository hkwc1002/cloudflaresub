import assert from 'node:assert/strict';
import worker from '../src/worker.js';

class MemoryKV {
  constructor() {
    this.map = new Map();
    this.putCalls = [];
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
    const keys = [...this.map.keys()]
      .filter((key) => key.startsWith(prefix))
      .sort()
      .map((name) => ({ name }));
    return { keys, list_complete: true };
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
assert.equal(response.status, 404, 'deleted subscription must disappear');

console.log('worker security test passed');
