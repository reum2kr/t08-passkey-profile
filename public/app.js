// Private-area client script.
// Talks to navigator.credentials.create()/get() directly — no
// @simplewebauthn/browser or any other library, just the small
// base64url<->ArrayBuffer helpers below (the npm registry is blocked in
// the dev session this was built in, so everything here is hand-rolled).
(function () {
  'use strict';

  function b64uToBuf(b64u) {
    const pad = '='.repeat((4 - (b64u.length % 4)) % 4);
    const base64 = (b64u + pad).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(base64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } }, opts));
    let body = null;
    try { body = await res.json(); } catch (e) { /* no body */ }
    return { ok: res.ok, status: res.status, body };
  }

  const lockedMsg = document.getElementById('lockedMsg');
  const unlockedMsg = document.getElementById('unlockedMsg');
  function setMsg(el, text, kind) {
    el.textContent = text || '';
    el.className = 'priv-msg' + (kind ? ' ' + kind : '');
  }

  // ---- tabs ----
  const tabLogin = document.getElementById('tabLogin');
  const tabRegister = document.getElementById('tabRegister');
  const paneLogin = document.getElementById('paneLogin');
  const paneRegister = document.getElementById('paneRegister');
  tabLogin.addEventListener('click', () => {
    tabLogin.classList.add('active'); tabRegister.classList.remove('active');
    paneLogin.hidden = false; paneRegister.hidden = true; setMsg(lockedMsg, '');
  });
  tabRegister.addEventListener('click', () => {
    tabRegister.classList.add('active'); tabLogin.classList.remove('active');
    paneRegister.hidden = false; paneLogin.hidden = true; setMsg(lockedMsg, '');
  });

  // ---- registration (new account) ----
  document.getElementById('btnRegister').addEventListener('click', async () => {
    const username = document.getElementById('registerUsername').value.trim();
    const deviceName = document.getElementById('registerDeviceName').value.trim() || '이 기기';
    if (!username) return setMsg(lockedMsg, '아이디를 입력하세요', 'err');
    setMsg(lockedMsg, '패스키 등록을 시작합니다...');

    const start = await api('/api/register/start', { method: 'POST', body: JSON.stringify({ username, deviceName }) });
    if (!start.ok) return setMsg(lockedMsg, start.body.error || '등록 시작 실패', 'err');

    const opts = start.body;
    const publicKey = {
      rp: opts.rp,
      user: { id: b64uToBuf(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
      challenge: b64uToBuf(opts.challenge),
      pubKeyCredParams: opts.pubKeyCredParams,
      timeout: opts.timeout,
      attestation: opts.attestation,
      authenticatorSelection: opts.authenticatorSelection,
      excludeCredentials: opts.excludeCredentials.map((c) => ({ type: c.type, id: b64uToBuf(c.id) })),
    };

    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey });
    } catch (e) {
      // Cancelled or unsupported — nothing was ever sent to the server, so
      // nothing is stored (T08-C25).
      return setMsg(lockedMsg, '등록이 취소되었거나 실패했습니다: ' + e.message, 'err');
    }

    const credentialForServer = {
      id: bufToB64u(cred.rawId),
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    };

    const finish = await api('/api/register/finish', { method: 'POST', body: JSON.stringify({ credential: credentialForServer }) });
    if (!finish.ok) return setMsg(lockedMsg, finish.body.error || '등록 완료 실패', 'err');
    setMsg(lockedMsg, '등록 완료! 들어갑니다...', 'ok');
    await refreshAll();
  });

  // ---- login ----
  document.getElementById('btnLogin').addEventListener('click', async () => {
    const username = document.getElementById('loginUsername').value.trim();
    if (!username) return setMsg(lockedMsg, '아이디를 입력하세요', 'err');
    setMsg(lockedMsg, '패스키로 로그인 중...');

    const start = await api('/api/login/start', { method: 'POST', body: JSON.stringify({ username }) });
    if (!start.ok) return setMsg(lockedMsg, start.body.error || '로그인 시작 실패', 'err');

    const opts = start.body;
    const publicKey = {
      challenge: b64uToBuf(opts.challenge),
      timeout: opts.timeout,
      rpId: opts.rpId,
      userVerification: opts.userVerification,
      allowCredentials: opts.allowCredentials.map((c) => ({ type: c.type, id: b64uToBuf(c.id) })),
    };

    let assertion;
    try {
      assertion = await navigator.credentials.get({ publicKey });
    } catch (e) {
      return setMsg(lockedMsg, '로그인이 취소되었거나 이 기기에 맞는 패스키가 없습니다: ' + e.message, 'err');
    }

    const credentialForServer = {
      id: bufToB64u(assertion.rawId),
      response: {
        clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
        authenticatorData: bufToB64u(assertion.response.authenticatorData),
        signature: bufToB64u(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null,
      },
    };

    const finish = await api('/api/login/finish', { method: 'POST', body: JSON.stringify({ credential: credentialForServer }) });
    if (!finish.ok) return setMsg(lockedMsg, finish.body.error || '로그인 실패', 'err');
    setMsg(lockedMsg, '로그인 성공', 'ok');
    await refreshAll();
  });

  // ---- add a second passkey to the current account ----
  document.getElementById('btnAddPasskey').addEventListener('click', async () => {
    const deviceName = prompt('이 패스키를 등록할 기기/브라우저 이름을 입력하세요 (예: 휴대폰)') || '추가 기기';
    setMsg(unlockedMsg, '두 번째 패스키 등록 중...');
    const start = await api('/api/register/start', { method: 'POST', body: JSON.stringify({ deviceName }) });
    if (!start.ok) return setMsg(unlockedMsg, start.body.error || '등록 시작 실패', 'err');
    const opts = start.body;
    const publicKey = {
      rp: opts.rp,
      user: { id: b64uToBuf(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
      challenge: b64uToBuf(opts.challenge),
      pubKeyCredParams: opts.pubKeyCredParams,
      timeout: opts.timeout,
      attestation: opts.attestation,
      authenticatorSelection: opts.authenticatorSelection,
      excludeCredentials: opts.excludeCredentials.map((c) => ({ type: c.type, id: b64uToBuf(c.id) })),
    };
    let cred;
    try { cred = await navigator.credentials.create({ publicKey }); }
    catch (e) { return setMsg(unlockedMsg, '취소되었거나 실패: ' + e.message, 'err'); }
    const credentialForServer = {
      id: bufToB64u(cred.rawId),
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    };
    const finish = await api('/api/register/finish', { method: 'POST', body: JSON.stringify({ credential: credentialForServer }) });
    if (!finish.ok) return setMsg(unlockedMsg, finish.body.error || '등록 완료 실패', 'err');
    setMsg(unlockedMsg, '두 번째 패스키 등록 완료', 'ok');
    await loadPasskeys();
  });

  document.getElementById('btnLogout').addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST' });
    await refreshAll();
  });

  document.getElementById('btnAddItem').addEventListener('click', async () => {
    const title = document.getElementById('newItemTitle').value.trim();
    const content = document.getElementById('newItemContent').value.trim();
    if (!title || !content) return setMsg(unlockedMsg, '제목과 내용을 입력하세요', 'err');
    const res = await api('/api/private/items', { method: 'POST', body: JSON.stringify({ title, content }) });
    if (!res.ok) return setMsg(unlockedMsg, res.body.error || '추가 실패', 'err');
    document.getElementById('newItemTitle').value = '';
    document.getElementById('newItemContent').value = '';
    await loadItems();
  });

  async function loadPasskeys() {
    const res = await api('/api/passkeys');
    if (!res.ok) return;
    const list = document.getElementById('passkeyList');
    list.innerHTML = '';
    res.body.passkeys.forEach((pk) => {
      const row = document.createElement('div');
      row.className = 'priv-key-row';
      const created = new Date(pk.created_at + 'Z').toLocaleString('ko-KR');
      row.innerHTML =
        '<div><div class="priv-key-name">' + escapeHtml(pk.device_name) + '</div>' +
        '<div class="priv-key-date">등록: ' + created + (pk.last_used_at ? ' · 최근 로그인: ' + new Date(pk.last_used_at + 'Z').toLocaleString('ko-KR') : '') + '</div></div>';
      const btn = document.createElement('button');
      btn.className = 'priv-btn danger'; btn.textContent = '삭제'; btn.style.padding = '6px 12px';
      btn.addEventListener('click', async () => {
        if (!confirm('이 패스키를 삭제할까요? 마지막 하나만 남아 있으면 삭제되지 않습니다.')) return;
        const del = await api('/api/passkeys/' + pk.id, { method: 'DELETE' });
        setMsg(unlockedMsg, del.ok ? '삭제되었습니다' : (del.body.error || '삭제 실패'), del.ok ? 'ok' : 'err');
        await loadPasskeys();
      });
      row.appendChild(btn);
      list.appendChild(row);
    });
  }

  async function loadItems() {
    const res = await api('/api/private/items');
    if (!res.ok) return;
    const list = document.getElementById('itemList');
    list.innerHTML = '';
    if (res.body.items.length === 0) list.innerHTML = '<p style="color:var(--muted-dark);font-size:13px;">아직 항목이 없습니다.</p>';
    res.body.items.forEach((item) => {
      const div = document.createElement('div');
      div.className = 'priv-item';
      const created = new Date(item.created_at + 'Z').toLocaleString('ko-KR');
      div.innerHTML = '<h4>' + escapeHtml(item.title) + '</h4><p>' + escapeHtml(item.content) + '</p><time>' + created + '</time>';
      list.appendChild(div);
    });
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  async function refreshAll() {
    const res = await api('/api/session');
    const locked = document.getElementById('private-locked');
    const unlocked = document.getElementById('private-unlocked');
    if (res.ok && res.body.loggedIn) {
      locked.hidden = true; unlocked.hidden = false;
      document.getElementById('whoAmI').textContent = res.body.username;
      await Promise.all([loadPasskeys(), loadItems()]);
    } else {
      locked.hidden = false; unlocked.hidden = true;
    }
  }

  refreshAll();
})();
