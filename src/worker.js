// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
      'access-control-allow-headers': 'content-type,x-admin-token,authorization',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, remark = ''] = line.split('#');
      const value = raw.trim();
      const hashRemark = remark.trim();
      const match = value.match(/^(.*?)(?::(\d+))?$/);
      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: hashRemark,
      };
    });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network: u.searchParams.get('type') || 'tcp',
    tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls',
    host: u.searchParams.get('host') || u.searchParams.get('sni') || '',
    path: u.searchParams.get('path') || '/',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || '',
    fp: u.searchParams.get('fp') || '',
    alpn: u.searchParams.get('alpn') || '',
    flow: u.searchParams.get('flow') || '',
  };
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) {
      result.push(parseVmess(line));
      continue;
    }
    if (line.startsWith('vless://')) {
      result.push(parseUrlLike(line, 'vless'));
      continue;
    }
    if (line.startsWith('trojan://')) {
      result.push(parseUrlLike(line, 'trojan'));
      continue;
    }
    try {
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch {}
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      output.push({
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : '',
        sni: options.keepOriginalHost ? node.sni : '',
      });
    }
  }
  return output;
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  const lines = nodes
    .map((node) => {
      if (node.type === 'vmess') return encodeVmess(node);
      if (node.type === 'vless') return encodeVless(node);
      if (node.type === 'trojan') return encodeTrojan(node);
      return '';
    })
    .filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes
    .map((node) => {
      if (node.type === 'vmess') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vmess`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    alterId: 0`,
          `    cipher: ${node.cipher || 'auto'}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'vless') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vless`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'trojan') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: trojan`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];

        if (node.sni) {
          lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        }

        if (node.tls !== false) {
          lines.push(`    tls: true`);
        }

        if (node.network) {
          lines.push(`    network: ${node.network}`);
        }

        if (node.network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      return '';
    })
    .filter(Boolean);

  const proxyNames = nodes.map(
    (node) => `      - "${escapeYaml(node.name)}"`
  );

  const allGroupMembers = [
    `      - "自动选择"`,
    ...proxyNames,
    `      - DIRECT`,
  ];

  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...(proxies.length ? proxies : []),
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter((node) => node.type === 'vmess' || node.type === 'trojan')
    .map((node) => {
      if (node.type === 'vmess') {
        return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
      }
      return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
    });

  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = select, ' +
      nodes
        .filter((n) => n.type === 'vmess' || n.type === 'trojan')
        .map((n) => n.name)
        .join(', '),
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    '; token-protected subscription',
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}


function constantTimeEqual(a = '', b = '') {
  const left = String(a);
  const right = String(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < length; i++) {
    diff |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
  }
  return diff === 0;
}

function getAdminToken(request) {
  const direct = request.headers.get('x-admin-token') || '';
  if (direct) return direct;
  const authorization = request.headers.get('authorization') || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1] || '';
}

function validateAdmin(request, env) {
  const expected = env.SUB_ADMIN_TOKEN || '';
  if (!expected) {
    return {
      ok: false,
      response: json(
        { ok: false, error: '未配置 SUB_ADMIN_TOKEN，管理接口已禁用。' },
        503,
      ),
    };
  }
  const provided = getAdminToken(request);
  if (!provided || !constantTimeEqual(provided, expected)) {
    return {
      ok: false,
      response: json({ ok: false, error: '管理员令牌无效。' }, 403),
    };
  }
  return { ok: true };
}

function randomBase64Url(byteLength = 18) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function deriveSubscriptionToken(env, id, nonce) {
  const secret = String(env.SUB_ACCESS_TOKEN || '');
  if (!secret) {
    throw new Error('未配置 SUB_ACCESS_TOKEN。');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(id + ':' + nonce),
    ),
  );
  let binary = '';
  signature.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function getPayload(record) {
  if (record?.schemaVersion === 2 && record.payload) {
    return record.payload;
  }
  return record;
}

function isActiveV2Record(record) {
  return Boolean(record?.schemaVersion === 2 && record.status === 'active');
}

async function buildSubscriptionUrls(origin, id, record, env) {
  const token = await deriveSubscriptionToken(env, id, record.tokenNonce);
  const make = (target = '') => {
    const params = new URLSearchParams();
    if (target) params.set('target', target);
    params.set('token', token);
    return origin + '/sub/' + id + '?' + params.toString();
  };
  return {
    auto: make(''),
    raw: make('raw'),
    clash: make('clash'),
    surge: make('surge'),
  };
}

async function generateResponse(origin, id, record, counts, preview) {
  return {
    ok: true,
    storage: 'kv',
    deduplicated: Boolean(record.reused),
    shortId: id,
    urls: record.urls,
    counts,
    preview,
    warnings: [],
  };
}

async function handleGenerate(request, env, url) {
  const adminCheck = validateAdmin(request, env);
  if (!adminCheck.ok) return adminCheck.response;

  if (!env.SUB_ACCESS_TOKEN) {
    return json(
      { ok: false, error: '未配置 SUB_ACCESS_TOKEN，无法签发订阅访问令牌。' },
      503,
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  const baseNodes = parseRawLinks(body.nodeLinks || '');
  const preferredEndpoints = parsePreferredEndpoints(body.preferredIps || '');

  if (!baseNodes.length) return json({ ok: false, error: '没有识别到可用节点' }, 400);
  if (!preferredEndpoints.length) return json({ ok: false, error: '没有识别到可用优选地址' }, 400);

  const options = {
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
  };

  const nodes = buildNodes(baseNodes, preferredEndpoints, options);
  const payload = {
    version: 2,
    createdAt: new Date().toISOString(),
    options,
    nodes,
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = 'dedup:' + dedupHash;
  let id = await env.SUB_STORE.get(dedupKey);

  if (id) {
    const rawExisting = await env.SUB_STORE.get('sub:' + id);
    if (rawExisting) {
      try {
        const existing = JSON.parse(rawExisting);
        if (isActiveV2Record(existing)) {
          const urls = await buildSubscriptionUrls(url.origin, id, existing, env);
          return json(
            await generateResponse(
              url.origin,
              id,
              { ...existing, urls, reused: true },
              {
                inputNodes: baseNodes.length,
                preferredEndpoints: preferredEndpoints.length,
                outputNodes: nodes.length,
              },
              nodes.slice(0, 20).map((node) => ({
                name: node.name,
                type: node.type,
                server: node.server,
                port: node.port,
                host: node.host || '',
                sni: node.sni || '',
              })),
            ),
          );
        }
      } catch {
        // Corrupt or legacy records are replaced by a new v2 subscription.
      }
    }
  }

  id = await createUniqueShortId(env);
  const now = new Date().toISOString();
  const record = {
    schemaVersion: 2,
    status: 'active',
    createdAt: now,
    updatedAt: now,
    revokedAt: null,
    dedupKey,
    tokenNonce: randomBase64Url(18),
    payload,
  };

  // No expirationTtl: subscriptions remain valid until explicitly revoked/deleted.
  await env.SUB_STORE.put('sub:' + id, JSON.stringify(record));
  await env.SUB_STORE.put(dedupKey, id);

  const urls = await buildSubscriptionUrls(url.origin, id, record, env);
  return json(
    await generateResponse(
      url.origin,
      id,
      { ...record, urls, reused: false },
      {
        inputNodes: baseNodes.length,
        preferredEndpoints: preferredEndpoints.length,
        outputNodes: nodes.length,
      },
      nodes.slice(0, 20).map((node) => ({
        name: node.name,
        type: node.type,
        server: node.server,
        port: node.port,
        host: node.host || '',
        sni: node.sni || '',
      })),
    ),
  );
}

async function validateSubscriptionAccess(url, env, id, record) {
  const provided = url.searchParams.get('token') || '';

  if (record?.schemaVersion === 2) {
    if (record.status === 'revoked') {
      return { ok: false, response: text('revoked', 410) };
    }
    if (record.status !== 'active') {
      return { ok: false, response: text('not found', 404) };
    }
    if (!env.SUB_ACCESS_TOKEN) {
      return { ok: false, response: text('subscription token service unavailable', 503) };
    }
    const expected = await deriveSubscriptionToken(env, id, record.tokenNonce || '');
    if (!provided || !constantTimeEqual(provided, expected)) {
      return { ok: false, response: text('Forbidden: invalid token', 403) };
    }
    return { ok: true };
  }

  // Backward compatibility for surviving legacy records.
  const legacyExpected = env.SUB_ACCESS_TOKEN || '';
  if (legacyExpected && (!provided || !constantTimeEqual(provided, legacyExpected))) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

async function handleSub(url, env) {
  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await env.SUB_STORE.get('sub:' + id);
  if (!raw) return text('not found', 404);

  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    return text('invalid subscription record', 500);
  }

  const accessCheck = await validateSubscriptionAccess(url, env, id, record);
  if (!accessCheck.ok) return accessCheck.response;

  const payload = getPayload(record) || {};
  const nodes = payload.nodes || [];
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') {
    return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  }
  if (target === 'surge') {
    return text(
      renderSurge(nodes, url.origin + url.pathname, url.searchParams.get('token') || ''),
      200,
      'text/plain; charset=utf-8',
    );
  }
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

async function listAllSubscriptionKeys(env) {
  const keys = [];
  let cursor;
  do {
    const page = await env.SUB_STORE.list({ prefix: 'sub:', cursor });
    keys.push(...(page.keys || []));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return keys;
}

async function handleListSubscriptions(request, env) {
  const adminCheck = validateAdmin(request, env);
  if (!adminCheck.ok) return adminCheck.response;

  const keys = await listAllSubscriptionKeys(env);
  const items = await Promise.all(
    keys.map(async (key) => {
      const raw = await env.SUB_STORE.get(key.name);
      if (!raw) return null;
      try {
        const record = JSON.parse(raw);
        const payload = getPayload(record) || {};
        const id = key.name.slice('sub:'.length);
        return {
          id,
          status: record?.schemaVersion === 2 ? record.status : 'legacy',
          createdAt: record?.createdAt || payload.createdAt || '',
          updatedAt: record?.updatedAt || '',
          revokedAt: record?.revokedAt || null,
          nodeCount: Array.isArray(payload.nodes) ? payload.nodes.length : 0,
          namePrefix: payload.options?.namePrefix || '',
        };
      } catch {
        return {
          id: key.name.slice('sub:'.length),
          status: 'invalid',
          createdAt: '',
          updatedAt: '',
          revokedAt: null,
          nodeCount: 0,
          namePrefix: '',
        };
      }
    }),
  );

  return json({
    ok: true,
    subscriptions: items
      .filter(Boolean)
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))),
  });
}

async function removeDedupMappingIfOwned(env, record, id) {
  const dedupKey = record?.dedupKey;
  if (!dedupKey) return;
  const mappedId = await env.SUB_STORE.get(dedupKey);
  if (mappedId === id) {
    await env.SUB_STORE.delete(dedupKey);
  }
}

async function handleRevokeSubscription(request, env, id) {
  const adminCheck = validateAdmin(request, env);
  if (!adminCheck.ok) return adminCheck.response;

  const raw = await env.SUB_STORE.get('sub:' + id);
  if (!raw) return json({ ok: false, error: '订阅不存在。' }, 404);

  let current;
  try {
    current = JSON.parse(raw);
  } catch {
    return json({ ok: false, error: '订阅记录损坏。' }, 500);
  }

  if (current?.schemaVersion === 2 && current.status === 'revoked') {
    return json({ ok: true, id, status: 'revoked' });
  }

  const payload = getPayload(current);
  const now = new Date().toISOString();
  const next =
    current?.schemaVersion === 2
      ? { ...current, status: 'revoked', revokedAt: now, updatedAt: now }
      : {
          schemaVersion: 2,
          status: 'revoked',
          createdAt: current?.createdAt || now,
          updatedAt: now,
          revokedAt: now,
          dedupKey: '',
          tokenNonce: randomBase64Url(18),
          payload,
        };

  await env.SUB_STORE.put('sub:' + id, JSON.stringify(next));
  await removeDedupMappingIfOwned(env, next, id);
  return json({ ok: true, id, status: 'revoked' });
}

async function handleReissueSubscription(request, env, url, id) {
  const adminCheck = validateAdmin(request, env);
  if (!adminCheck.ok) return adminCheck.response;
  if (!env.SUB_ACCESS_TOKEN) {
    return json(
      { ok: false, error: '未配置 SUB_ACCESS_TOKEN，无法重新签发。' },
      503,
    );
  }

  const raw = await env.SUB_STORE.get('sub:' + id);
  if (!raw) return json({ ok: false, error: '订阅不存在。' }, 404);

  let current;
  try {
    current = JSON.parse(raw);
  } catch {
    return json({ ok: false, error: '订阅记录损坏。' }, 500);
  }

  const payload = getPayload(current);
  if (!payload?.nodes?.length) {
    return json({ ok: false, error: '订阅中没有可重新签发的节点。' }, 400);
  }

  const now = new Date().toISOString();
  const oldRecord =
    current?.schemaVersion === 2
      ? { ...current, status: 'revoked', revokedAt: now, updatedAt: now }
      : {
          schemaVersion: 2,
          status: 'revoked',
          createdAt: current?.createdAt || now,
          updatedAt: now,
          revokedAt: now,
          dedupKey: '',
          tokenNonce: randomBase64Url(18),
          payload,
        };
  await env.SUB_STORE.put('sub:' + id, JSON.stringify(oldRecord));

  const newId = await createUniqueShortId(env);
  const next = {
    schemaVersion: 2,
    status: 'active',
    createdAt: now,
    updatedAt: now,
    revokedAt: null,
    dedupKey: oldRecord.dedupKey || '',
    tokenNonce: randomBase64Url(18),
    payload: {
      ...payload,
      createdAt: now,
    },
  };
  await env.SUB_STORE.put('sub:' + newId, JSON.stringify(next));

  if (next.dedupKey) {
    await env.SUB_STORE.put(next.dedupKey, newId);
  }

  const urls = await buildSubscriptionUrls(url.origin, newId, next, env);
  return json({
    ok: true,
    oldId: id,
    shortId: newId,
    urls,
    note: '旧订阅已吊销，新订阅已签发。已下载的旧节点配置仍需通过轮换节点凭据才能失效。',
  });
}

async function handleDeleteSubscription(request, env, id) {
  const adminCheck = validateAdmin(request, env);
  if (!adminCheck.ok) return adminCheck.response;

  const raw = await env.SUB_STORE.get('sub:' + id);
  if (!raw) return json({ ok: true, id, deleted: false });

  try {
    const record = JSON.parse(raw);
    await removeDedupMappingIfOwned(env, record, id);
  } catch {
    // Delete malformed records as well.
  }

  await env.SUB_STORE.delete('sub:' + id);
  return json({ ok: true, id, deleted: true });
}

function parseManagementRoute(pathname) {
  const match = pathname.match(/^\/api\/subscriptions\/([^/]+)\/(revoke|reissue)$/);
  if (match) {
    return { id: decodeURIComponent(match[1]), action: match[2] };
  }
  const deleteMatch = pathname.match(/^\/api\/subscriptions\/([^/]+)$/);
  if (deleteMatch) {
    return { id: decodeURIComponent(deleteMatch[1]), action: 'delete' };
  }
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
          'access-control-allow-headers': 'content-type,x-admin-token,authorization',
        },
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }

    if (request.method === 'GET' && url.pathname === '/api/subscriptions') {
      return handleListSubscriptions(request, env);
    }

    const managementRoute = parseManagementRoute(url.pathname);
    if (managementRoute) {
      if (request.method === 'POST' && managementRoute.action === 'revoke') {
        return handleRevokeSubscription(request, env, managementRoute.id);
      }
      if (request.method === 'POST' && managementRoute.action === 'reissue') {
        return handleReissueSubscription(request, env, url, managementRoute.id);
      }
      if (request.method === 'DELETE' && managementRoute.action === 'delete') {
        return handleDeleteSubscription(request, env, managementRoute.id);
      }
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(url, env);
    }

    return env.ASSETS.fetch(request);
  },
};
