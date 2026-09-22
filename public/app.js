const form = document.getElementById('generator-form');
const submitBtn = document.getElementById('submitBtn');
const fillDemoBtn = document.getElementById('fillDemoBtn');
const resultSection = document.getElementById('resultSection');
const warningBox = document.getElementById('warningBox');
const previewBody = document.getElementById('previewBody');

const autoUrl = document.getElementById('autoUrl');
const rawUrl = document.getElementById('rawUrl');
const clashUrl = document.getElementById('clashUrl');
const surgeUrl = document.getElementById('surgeUrl');
const emptyState = document.getElementById('emptyState');

const qrModal = document.getElementById('qrModal');
const qrCanvas = document.getElementById('qrCanvas');
const qrText = document.getElementById('qrText');
const closeQrModal = document.getElementById('closeQrModal');

const adminTokenInput = document.getElementById('adminToken');
const saveAdminTokenBtn = document.getElementById('saveAdminTokenBtn');
const clearAdminTokenBtn = document.getElementById('clearAdminTokenBtn');
const refreshSubscriptionsBtn = document.getElementById('refreshSubscriptionsBtn');
const adminStatus = document.getElementById('adminStatus');
const runHealthCheckBtn = document.getElementById('runHealthCheckBtn');
const subscriptionTableBody = document.getElementById('subscriptionTableBody');
const subscriptionEmpty = document.getElementById('subscriptionEmpty');

const ADMIN_TOKEN_STORAGE_KEY = 'cfsub.adminToken';

const demoVmess = [
  'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJkZW1vLXdzLXRscyIsCiAgImFkZCI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAicG9ydCI6ICI0NDMiLAogICJpZCI6ICIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInRscyI6ICJ0bHMiLAogICJwYXRoIjogIi93cyIsCiAgImhvc3QiOiAiZWRnZS5leGFtcGxlLmNvbSIsCiAgInNuaSI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAiZnAiOiAiY2hyb21lIiwKICAiYWxwbiI6ICJoMixodHRwLzEuMSIKfQ=='
].join('\n');

const demoIps = [
  '104.16.1.2#HK-01',
  '104.17.2.3#HK-02',
  '104.18.3.4:2053#US-Edge'
].join('\n');

function getAdminToken() {
  return sessionStorage.getItem(ADMIN_TOKEN_STORAGE_KEY) || '';
}

function setAdminStatus(message, tone = 'muted') {
  adminStatus.textContent = message;
  adminStatus.dataset.tone = tone;
}

function requireAdminToken() {
  const token = getAdminToken();
  if (!token) {
    throw new Error('请先在“管理认证”中输入并保存 SUB_ADMIN_TOKEN。');
  }
  return token;
}

async function adminFetch(url, options = {}) {
  const token = requireAdminToken();
  const headers = new Headers(options.headers || {});
  headers.set('x-admin-token', token);
  const response = await fetch(url, { ...options, headers });
  let data;
  try {
    data = await response.json();
  } catch {
    data = { ok: false, error: '服务器返回了非 JSON 响应。' };
  }
  if (!response.ok || data.ok === false) {
    // Prefer the actionable `code` when the backend supplies one, so the UI can
    // explain an unbound KV namespace instead of showing a generic failure.
    throw new Error(describeApiError(data, response.status));
  }
  return data;
}

const ERROR_HINTS = {
  KV_BINDING_MISSING:
    '未绑定 KV namespace。请在 Cloudflare Dashboard → 该 Worker → Settings → Bindings 添加 Variable name 为 SUB_STORE 的 KV namespace 绑定，然后重新部署。',
  KV_BINDING_INVALID:
    'SUB_STORE 绑定类型不对。它必须绑定为 KV namespace，不能在 Variables 里当成文本变量或 Secret。',
  KV_LIST_FAILED: '读取 KV 失败，请检查 KV namespace 是否归属同一账号、绑定是否指向正确的 namespace。',
  HEALTHCHECK_FAILED: '请按上方未通过的项目逐项检查 Worker 的 Bindings 与 Secrets 配置。',
};

// Checks that actually block subscription management. `assetsBinding` is
// reported by /api/health but does not affect the API, so it must not stop the
// subscription list from loading.
const BLOCKING_CHECKS = ['kvBinding', 'kvReadWrite'];

function healthBlocksSubscriptionLoad(health) {
  const checks = health?.checks || {};
  return BLOCKING_CHECKS.some((key) => checks[key] && checks[key] !== 'ok');
}
function describeApiError(data, status) {
  const base = data?.error || ('请求失败：HTTP ' + status);
  const hint = data?.code ? ERROR_HINTS[data.code] : '';
  if (hint && !base.includes(hint)) {
    return base + '\n\n' + hint;
  }
  return base;
}

async function runHealthCheck({ quiet = false } = {}) {
  const token = getAdminToken();
  if (!token) {
    setAdminStatus('请先输入并保存 SUB_ADMIN_TOKEN，再运行环境自检。', 'danger');
    return null;
  }

  if (!quiet) setAdminStatus('正在运行环境自检...');

  try {
    const response = await fetch('/api/health', {
      headers: { 'x-admin-token': token },
    });
    const data = await response.json();
    const checks = data?.checks || {};
    const text = [
      'KV 绑定: ' + (checks.kvBinding || '?'),
      'KV 读写: ' + (checks.kvReadWrite || '?'),
      '静态资源绑定: ' + (checks.assetsBinding || '?'),
      'SUB_ACCESS_TOKEN: ' + (checks.accessToken || '?'),
    ].join('；');

    if (data?.ok) {
      setAdminStatus('环境自检通过 — ' + text, 'ok');
    } else {
      const lines = ['环境自检未通过 — ' + text];
      // Show the backend's failing-item summary: without it a failure caused by
      // a check that is not in the line above (e.g. assetsBinding) is invisible.
      if (data?.error) lines.push(data.error);
      if (checks.kvError) lines.push('KV 错误：' + checks.kvError);
      const hint = data?.code ? ERROR_HINTS[data.code] : '';
      if (hint) lines.push(hint);
      setAdminStatus(lines.join('\n'), 'danger');
    }
    return data;
  } catch (error) {
    if (!quiet) setAdminStatus('自检请求失败：' + (error.message || '未知错误'), 'danger');
    return null;
  }
}

const savedAdminToken = getAdminToken();
if (savedAdminToken) {
  adminTokenInput.value = savedAdminToken;
  setAdminStatus('本标签页已保存管理员令牌。', 'ok');
} else {
  setAdminStatus('管理员令牌只保存在当前标签页会话中，关闭标签页后清除。');
}

saveAdminTokenBtn.addEventListener('click', async () => {
  const value = adminTokenInput.value.trim();
  if (!value) {
    setAdminStatus('管理员令牌不能为空。', 'danger');
    return;
  }
  sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, value);
  setAdminStatus('已保存到当前标签页会话。', 'ok');

  // Run the environment self-check first. Only a broken KV binding can stop the
  // subscription list from loading; an unrelated failure (e.g. ASSETS) must not
  // block it, so gate on the blocking checks rather than `health.ok`.
  const health = await runHealthCheck({ quiet: true });
  if (healthBlocksSubscriptionLoad(health)) {
    return;
  }

  try {
    await loadSubscriptions();
  } catch (error) {
    setAdminStatus(error.message || '管理员令牌验证失败。', 'danger');
  }
});

if (runHealthCheckBtn) {
  runHealthCheckBtn.addEventListener('click', async () => {
    await runHealthCheck();
  });
}

clearAdminTokenBtn.addEventListener('click', () => {
  sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  adminTokenInput.value = '';
  subscriptionTableBody.innerHTML = '';
  subscriptionEmpty.classList.remove('hidden');
  setAdminStatus('已清除当前标签页中的管理员令牌。');
});

refreshSubscriptionsBtn.addEventListener('click', async () => {
  try {
    await loadSubscriptions();
  } catch (error) {
    showWarning(error.message || '刷新订阅列表失败。');
  }
});

fillDemoBtn.addEventListener('click', () => {
  document.getElementById('nodeLinks').value = demoVmess;
  document.getElementById('preferredIps').value = demoIps;
  document.getElementById('namePrefix').value = 'CF';
  document.getElementById('keepOriginalHost').checked = true;
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  warningBox.classList.add('hidden');
  previewBody.innerHTML = '';

  const payload = {
    nodeLinks: document.getElementById('nodeLinks').value,
    preferredIps: document.getElementById('preferredIps').value,
    namePrefix: document.getElementById('namePrefix').value,
    keepOriginalHost: document.getElementById('keepOriginalHost').checked,
  };

  submitBtn.disabled = true;
  submitBtn.textContent = '生成中...';

  try {
    const data = await adminFetch('/api/generate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });

    applyGeneratedResult(data);
    await loadSubscriptions();
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    showWarning(error.message || '请求失败');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = '生成订阅';
  }
});

function applyGeneratedResult(data) {
  autoUrl.value = data.urls?.auto || '';
  rawUrl.value = data.urls?.raw || '';
  document.getElementById('rocketUrl').value = data.urls?.raw || '';
  clashUrl.value = data.urls?.clash || '';
  surgeUrl.value = data.urls?.surge || '';

  emptyState.classList.add('hidden');

  document.getElementById('statInputNodes').textContent = data.counts?.inputNodes ?? '-';
  document.getElementById('statEndpoints').textContent = data.counts?.preferredEndpoints ?? '-';
  document.getElementById('statOutputNodes').textContent = data.counts?.outputNodes ?? '-';

  previewBody.innerHTML = (data.preview || []).map((item) => {
    return '<tr>' +
      '<td>' + escapeHtml(item.name) + '</td>' +
      '<td>' + escapeHtml(item.type) + '</td>' +
      '<td>' + escapeHtml(item.server) + '</td>' +
      '<td>' + escapeHtml(String(item.port)) + '</td>' +
      '<td>' + escapeHtml(item.host || '-') + '</td>' +
      '<td>' + escapeHtml(item.sni || '-') + '</td>' +
      '</tr>';
  }).join('');

  if (Array.isArray(data.warnings) && data.warnings.length) {
    showWarning(data.warnings.join('\n'));
  }
}

async function loadSubscriptions() {
  const data = await adminFetch('/api/subscriptions');
  const rows = data.subscriptions || [];
  subscriptionTableBody.innerHTML = '';

  if (!rows.length) {
    subscriptionEmpty.classList.remove('hidden');
    setAdminStatus('管理员令牌有效；当前没有可管理的订阅。', 'ok');
    return;
  }

  subscriptionEmpty.classList.add('hidden');
  subscriptionTableBody.innerHTML = rows.map(renderSubscriptionRow).join('');

  // `truncated` means KV pagination stalled, so the list is incomplete and the
  // admin must not be told every subscription was loaded.
  if (data.truncated) {
    setAdminStatus(
      '管理员令牌有效；已加载 ' + rows.length + ' 条订阅，但 KV 分页未完成，列表可能不完整，请刷新重试。',
      'danger',
    );
  } else {
    setAdminStatus('管理员令牌有效；已加载 ' + rows.length + ' 条订阅。', 'ok');
  }
}

function renderSubscriptionRow(item) {
  const status = item.status || 'unknown';
  const canReissue = status !== 'invalid';
  const canRevoke = status === 'active' || status === 'legacy';
  const disabledReissue = canReissue ? '' : ' disabled';
  const disabledRevoke = canRevoke ? '' : ' disabled';

  return '<tr>' +
    '<td><code>' + escapeHtml(item.id) + '</code></td>' +
    '<td><span class="status-badge status-' + escapeHtml(status) + '">' + escapeHtml(status) + '</span></td>' +
    '<td>' + escapeHtml(formatDate(item.createdAt)) + '</td>' +
    '<td>' + escapeHtml(String(item.nodeCount ?? 0)) + '</td>' +
    '<td>' + escapeHtml(item.namePrefix || '-') + '</td>' +
    '<td class="management-actions">' +
      '<button type="button" class="secondary small" data-sub-action="reissue" data-sub-id="' + escapeHtml(item.id) + '"' + disabledReissue + '>重新签发</button>' +
      '<button type="button" class="secondary small" data-sub-action="revoke" data-sub-id="' + escapeHtml(item.id) + '"' + disabledRevoke + '>吊销</button>' +
      '<button type="button" class="danger small" data-sub-action="delete" data-sub-id="' + escapeHtml(item.id) + '">删除</button>' +
    '</td>' +
  '</tr>';
}

function formatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

document.addEventListener('click', async (event) => {
  const managementButton = event.target.closest('[data-sub-action]');
  if (managementButton) {
    const action = managementButton.dataset.subAction;
    const id = managementButton.dataset.subId;
    if (!id) return;

    try {
      if (action === 'revoke') {
        if (!confirm('确认吊销订阅 ' + id + '？旧订阅链接将立即无法再次下载。')) return;
        await adminFetch('/api/subscriptions/' + encodeURIComponent(id) + '/revoke', { method: 'POST' });
        showWarning('订阅 ' + id + ' 已吊销。注意：已经下载到客户端的节点凭据不会因此自动失效。');
      }

      if (action === 'reissue') {
        if (!confirm('确认重新签发订阅 ' + id + '？旧订阅会被吊销，并生成新的 ID 与访问令牌。')) return;
        const data = await adminFetch('/api/subscriptions/' + encodeURIComponent(id) + '/reissue', { method: 'POST' });
        applyReissuedUrls(data);
        showWarning('重新签发成功。旧订阅已吊销，请尽快把客户端更新为新链接。');
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }

      if (action === 'delete') {
        if (!confirm('确认永久删除订阅记录 ' + id + '？该操作不可恢复。')) return;
        await adminFetch('/api/subscriptions/' + encodeURIComponent(id), { method: 'DELETE' });
        showWarning('订阅记录 ' + id + ' 已永久删除。');
      }

      await loadSubscriptions();
    } catch (error) {
      showWarning(error.message || '订阅管理操作失败。');
    }
    return;
  }

  const copyButton = event.target.closest('[data-copy-target]');
  if (copyButton) {
    const input = document.getElementById(copyButton.dataset.copyTarget);
    if (!input?.value) return;
    try {
      await navigator.clipboard.writeText(input.value);
      const originalText = copyButton.textContent;
      copyButton.textContent = '已复制';
      setTimeout(() => {
        copyButton.textContent = originalText;
      }, 1200);
    } catch {
      input.select();
      document.execCommand('copy');
    }
    return;
  }

  const qrButton = event.target.closest('[data-qrcode-target]');
  if (qrButton) {
    warningBox.classList.add('hidden');

    const input = document.getElementById(qrButton.dataset.qrcodeTarget);
    if (!input?.value) {
      showWarning('请先生成订阅链接，再显示二维码。');
      return;
    }

    if (!window.QRCode) {
      showWarning('二维码组件加载失败，请刷新页面后重试。');
      return;
    }

    qrCanvas.innerHTML = '';
    qrText.textContent = input.value;
    qrModal.classList.remove('hidden');
    qrModal.setAttribute('aria-hidden', 'false');

    new window.QRCode(qrCanvas, {
      text: input.value,
      width: 220,
      height: 220,
      correctLevel: window.QRCode.CorrectLevel.M,
    });
    return;
  }

  if (event.target.closest('[data-close-modal="true"]')) {
    closeQrDialog();
  }
});

function applyReissuedUrls(data) {
  const urls = data.urls || {};
  autoUrl.value = urls.auto || '';
  rawUrl.value = urls.raw || '';
  document.getElementById('rocketUrl').value = urls.raw || '';
  clashUrl.value = urls.clash || '';
  surgeUrl.value = urls.surge || '';
  emptyState.classList.add('hidden');
  document.getElementById('statInputNodes').textContent = '-';
  document.getElementById('statEndpoints').textContent = '-';
  document.getElementById('statOutputNodes').textContent = '-';
  previewBody.innerHTML = '';
}

function showWarning(message) {
  warningBox.textContent = message;
  warningBox.classList.remove('hidden');
}

closeQrModal.addEventListener('click', closeQrDialog);

function closeQrDialog() {
  qrModal.classList.add('hidden');
  qrModal.setAttribute('aria-hidden', 'true');
  qrCanvas.innerHTML = '';
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

if (savedAdminToken) {
  loadSubscriptions().catch((error) => {
    setAdminStatus(error.message || '无法加载订阅列表。', 'danger');
  });
}
