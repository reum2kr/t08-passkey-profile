'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { run, get, all } = require('./db');
const wa = require('./webauthn');

const PORT = process.env.PORT || 3000;
const RP_ID = process.env.RP_ID || 'localhost';
const RP_NAME = process.env.RP_NAME || 'Areum Jang — Private Space';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------------- session helpers (server-side, sqlite-backed) ----------------
const SESSION_COOKIE = 'sid';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function isSecureRequest(req) {
  if (req.headers['x-forwarded-proto']) return req.headers['x-forwarded-proto'] === 'https';
  return false;
}

function newSessionId() {
  return crypto.randomBytes(24).toString('base64url');
}

function loadSession(req) {
  const cookies = parseCookies(req);
  const sid = cookies[SESSION_COOKIE];
  if (sid) {
    const row = get('SELECT * FROM sessions WHERE id = ?', [sid]);
    if (row && new Date(row.expires_at) > new Date()) {
      return { id: sid, userId: row.user_id, pending: row.pending_json ? JSON.parse(row.pending_json) : {}, isNew: false };
    }
  }
  return { id: newSessionId(), userId: null, pending: {}, isNew: true };
}

function saveSession(res, session, req) {
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const pendingJson = JSON.stringify(session.pending || {});
  const existing = get('SELECT id FROM sessions WHERE id = ?', [session.id]);
  if (existing) {
    run('UPDATE sessions SET user_id = ?, pending_json = ?, expires_at = ? WHERE id = ?', [session.userId, pendingJson, expiresAt, session.id]);
  } else {
    run('INSERT INTO sessions (id, user_id, pending_json, expires_at) VALUES (?, ?, ?, ?)', [session.id, session.userId, pendingJson, expiresAt]);
  }
  const secure = isSecureRequest(req);
  const attrs = [`${SESSION_COOKIE}=${session.id}`, 'HttpOnly', 'Path=/', 'SameSite=Lax', `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`];
  if (secure) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

// ---------------- tiny HTTP helpers ----------------
function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(data) });
  res.end(data);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { reject(new Error('본문이 너무 큽니다')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('JSON 파싱 실패')); }
    });
    req.on('error', reject);
  });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.json': 'application/json' };

function serveStatic(req, res, pathname) {
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    res.writeHead(400); return res.end('Bad request');
  }
  let filePath = path.join(PUBLIC_DIR, decodedPath === '/' ? 'index.html' : decodedPath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------------- auth-required guard ----------------
function requireAuth(session, res) {
  if (!session.userId) {
    sendJson(res, 401, { error: '로그인이 필요합니다 (패스키로 인증되지 않음)' });
    return null;
  }
  const user = get('SELECT * FROM users WHERE id = ?', [session.userId]);
  if (!user) {
    sendJson(res, 401, { error: '세션의 사용자를 찾을 수 없습니다' });
    return null;
  }
  return user;
}

function seedDemoItems(userId, username) {
  const seeds = username === 'areum'
    ? [
        ['다음 스프린트 메모', '패스키 로그인 붙이는 작업(8번 과제) 끝나면 9번 준비. AI 코드리뷰 습관화하기.'],
        ['지원 후보 목록(가상)', 'A보안팀(가상), B사 보안엔지니어 포지션(가상) — 실제 지원 여부 아직 미정, 연습용 메모.'],
        ['이번 주 회고', '패스키는 비밀번호보다 등록 흐름 설계가 더 까다로웠다. challenge 재사용 막는 부분에서 한 번 막혔었음.'],
      ]
    : [
        ['개인 프로젝트 아이디어(가상)', '집 IoT 로그를 모아 보는 대시보드 — 아직 스케치 단계.'],
        ['면접 준비 메모(가상)', 'WebAuthn 챌린지/응답 구조 설명 연습.'],
        ['읽을 자료(가상)', 'FIDO2/CTAP2 스펙 요약본 다시 읽기.'],
      ];
  for (const [title, content] of seeds) {
    run('INSERT INTO private_items (user_id, title, content) VALUES (?, ?, ?)', [userId, title, content]);
  }
}

// ---------------- request handler ----------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const session = loadSession(req);

  try {
    if (pathname === '/api/session' && req.method === 'GET') {
      let username = null;
      if (session.userId) {
        const u = get('SELECT username FROM users WHERE id = ?', [session.userId]);
        username = u ? u.username : null;
      }
      saveSession(res, session, req);
      return sendJson(res, 200, { loggedIn: !!username, username });
    }

    // ---- registration: start (new account, or add passkey if logged in) ----
    if (pathname === '/api/register/start' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const username = String(body.username || '').trim();
      const deviceName = String(body.deviceName || '이 기기').trim().slice(0, 40);

      if (session.userId) {
        // adding an additional passkey to the current account
        const user = get('SELECT * FROM users WHERE id = ?', [session.userId]);
        if (!user) return sendJson(res, 401, { error: '세션이 유효하지 않습니다' });
        const existing = all('SELECT credential_id FROM credentials WHERE user_id = ?', [user.id]);
        const { optionsForClient, challenge } = wa.buildRegistrationOptions({
          rpID: RP_ID, rpName: RP_NAME, userHandle: Buffer.from(user.user_handle, 'base64url'),
          username: user.username, excludeCredentials: existing.map((c) => ({ credential_id: c.credential_id })),
        });
        session.pending = { type: 'register', mode: 'add', userId: user.id, deviceName, challenge: wa.b64u.encode(challenge), expiresAt: Date.now() + CHALLENGE_TTL_MS };
        saveSession(res, session, req);
        return sendJson(res, 200, optionsForClient);
      }

      if (!/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
        return sendJson(res, 400, { error: '아이디는 영문/숫자/-/_ 3~20자여야 합니다' });
      }
      const already = get('SELECT id FROM users WHERE username = ?', [username]);
      if (already) return sendJson(res, 409, { error: '이미 있는 아이디입니다. 로그인을 이용하세요.' });

      const userHandle = crypto.randomBytes(16);
      const { optionsForClient, challenge } = wa.buildRegistrationOptions({ rpID: RP_ID, rpName: RP_NAME, userHandle, username, excludeCredentials: [] });
      session.pending = { type: 'register', mode: 'new', username, userHandle: userHandle.toString('base64url'), deviceName, challenge: wa.b64u.encode(challenge), expiresAt: Date.now() + CHALLENGE_TTL_MS };
      saveSession(res, session, req);
      return sendJson(res, 200, optionsForClient);
    }

    // ---- registration: finish ----
    if (pathname === '/api/register/finish' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const pending = session.pending;
      if (!pending || pending.type !== 'register' || Date.now() > pending.expiresAt) {
        return sendJson(res, 400, { error: '등록 요청이 없거나 만료되었습니다. 처음부터 다시 시도하세요.' });
      }
      let verified;
      try {
        verified = wa.verifyRegistration({
          credential: body.credential,
          expectedChallenge: wa.b64u.decode(pending.challenge),
          expectedOrigin: ORIGIN,
          expectedRPID: RP_ID,
        });
      } catch (e) {
        return sendJson(res, 400, { error: '등록 검증 실패: ' + e.message });
      }

      // consume the challenge no matter what happens next (single-use)
      session.pending = {};

      let userId, username;
      if (pending.mode === 'new') {
        run('INSERT INTO users (user_handle, username) VALUES (?, ?)', [pending.userHandle, pending.username]);
        const u = get('SELECT * FROM users WHERE username = ?', [pending.username]);
        userId = u.id; username = u.username;
        seedDemoItems(userId, username);
      } else {
        userId = pending.userId;
        const u = get('SELECT username FROM users WHERE id = ?', [userId]);
        username = u.username;
      }

      run(
        'INSERT INTO credentials (user_id, credential_id, public_key_jwk, sign_count, device_name, transports) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, verified.credentialId, JSON.stringify(verified.publicKeyJwk), verified.signCount, pending.deviceName, JSON.stringify(body.credential.response.transports || [])]
      );

      session.userId = userId;
      saveSession(res, session, req);
      return sendJson(res, 200, { ok: true, username, deviceName: pending.deviceName });
    }

    // ---- login: start ----
    if (pathname === '/api/login/start' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const username = String(body.username || '').trim();
      const user = get('SELECT * FROM users WHERE username = ?', [username]);
      if (!user) return sendJson(res, 404, { error: '해당 아이디가 없습니다' });
      const creds = all('SELECT credential_id FROM credentials WHERE user_id = ?', [user.id]);
      if (creds.length === 0) return sendJson(res, 409, { error: '등록된 패스키가 없습니다' });

      const { optionsForClient, challenge } = wa.buildAuthenticationOptions({ rpID: RP_ID, allowCredentials: creds.map((c) => ({ credential_id: c.credential_id })) });
      session.pending = { type: 'login', userId: user.id, challenge: wa.b64u.encode(challenge), expiresAt: Date.now() + CHALLENGE_TTL_MS };
      saveSession(res, session, req);
      return sendJson(res, 200, optionsForClient);
    }

    // ---- login: finish ----
    if (pathname === '/api/login/finish' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const pending = session.pending;
      if (!pending || pending.type !== 'login' || Date.now() > pending.expiresAt) {
        return sendJson(res, 400, { error: '로그인 요청이 없거나 이미 처리(또는 만료)되었습니다. 다시 시도하세요.' });
      }
      const credentialIdB64u = body.credential && body.credential.id;
      const credRow = get('SELECT * FROM credentials WHERE credential_id = ? AND user_id = ?', [credentialIdB64u, pending.userId]);
      if (!credRow) {
        session.pending = {};
        saveSession(res, session, req);
        return sendJson(res, 400, { error: '해당 계정에 속하지 않은 패스키입니다' });
      }

      let result;
      try {
        result = wa.verifyAuthentication({
          credential: body.credential,
          expectedChallenge: wa.b64u.decode(pending.challenge),
          expectedOrigin: ORIGIN,
          expectedRPID: RP_ID,
          storedPublicKeyJwk: JSON.parse(credRow.public_key_jwk),
          storedSignCount: credRow.sign_count,
          alg: JSON.parse(credRow.public_key_jwk).crv ? -7 : -257,
        });
      } catch (e) {
        session.pending = {}; // single-use even on failure
        saveSession(res, session, req);
        return sendJson(res, 401, { error: '로그인 검증 실패: ' + e.message });
      }

      session.pending = {}; // consume challenge on success
      session.userId = pending.userId;
      run('UPDATE credentials SET sign_count = ?, last_used_at = datetime(\'now\') WHERE id = ?', [result.newSignCount, credRow.id]);
      const user = get('SELECT username FROM users WHERE id = ?', [pending.userId]);
      saveSession(res, session, req);
      return sendJson(res, 200, { ok: true, username: user.username });
    }

    // ---- logout ----
    if (pathname === '/api/logout' && req.method === 'POST') {
      session.userId = null;
      session.pending = {};
      saveSession(res, session, req);
      return sendJson(res, 200, { ok: true });
    }

    // ---- passkeys list / delete ----
    if (pathname === '/api/passkeys' && req.method === 'GET') {
      const user = requireAuth(session, res); if (!user) return;
      const rows = all('SELECT id, device_name, created_at, last_used_at FROM credentials WHERE user_id = ? ORDER BY created_at ASC', [user.id]);
      saveSession(res, session, req);
      return sendJson(res, 200, { passkeys: rows });
    }
    const passkeyDeleteMatch = pathname.match(/^\/api\/passkeys\/(\d+)$/);
    if (passkeyDeleteMatch && req.method === 'DELETE') {
      const user = requireAuth(session, res); if (!user) return;
      const id = Number(passkeyDeleteMatch[1]);
      const row = get('SELECT * FROM credentials WHERE id = ?', [id]);
      if (!row || row.user_id !== user.id) return sendJson(res, 404, { error: '해당 패스키를 찾을 수 없습니다' });
      const countRow = get('SELECT COUNT(*) as c FROM credentials WHERE user_id = ?', [user.id]);
      if (countRow.c <= 1) {
        return sendJson(res, 409, { error: '마지막 남은 패스키는 삭제할 수 없습니다 (삭제하면 이 계정에 다시 들어올 방법이 없어집니다)' });
      }
      run('DELETE FROM credentials WHERE id = ?', [id]);
      saveSession(res, session, req);
      return sendJson(res, 200, { ok: true });
    }

    // ---- private items ----
    if (pathname === '/api/private/items' && req.method === 'GET') {
      const user = requireAuth(session, res); if (!user) return;
      const rows = all('SELECT id, title, content, created_at FROM private_items WHERE user_id = ? ORDER BY created_at DESC', [user.id]);
      saveSession(res, session, req);
      return sendJson(res, 200, { items: rows });
    }
    if (pathname === '/api/private/items' && req.method === 'POST') {
      const user = requireAuth(session, res); if (!user) return;
      const body = await readJsonBody(req);
      const title = String(body.title || '').trim().slice(0, 100);
      const content = String(body.content || '').trim().slice(0, 2000);
      if (!title || !content) return sendJson(res, 400, { error: '제목과 내용을 입력하세요' });
      run('INSERT INTO private_items (user_id, title, content) VALUES (?, ?, ?)', [user.id, title, content]);
      const row = get('SELECT id, title, content, created_at FROM private_items WHERE id = last_insert_rowid()');
      saveSession(res, session, req);
      return sendJson(res, 201, { item: row });
    }
    const itemMatch = pathname.match(/^\/api\/private\/items\/(\d+)$/);
    if (itemMatch && req.method === 'GET') {
      const user = requireAuth(session, res); if (!user) return;
      const id = Number(itemMatch[1]);
      const row = get('SELECT id, user_id, title, content, created_at FROM private_items WHERE id = ?', [id]);
      if (!row) return sendJson(res, 404, { error: '항목이 없습니다' });
      if (row.user_id !== user.id) {
        // Ownership check: never trust a client-supplied id/user param — always
        // compare against the row's real owner from the DB.
        return sendJson(res, 403, { error: '다른 계정의 자료입니다' });
      }
      saveSession(res, session, req);
      return sendJson(res, 200, { item: { id: row.id, title: row.title, content: row.content, created_at: row.created_at } });
    }

    // ---- static files (public portfolio + private-area front end) ----
    if (req.method === 'GET' && !pathname.startsWith('/api/')) {
      return serveStatic(req, res, pathname);
    }

    return sendJson(res, 404, { error: 'not found' });
  } catch (e) {
    console.error(e);
    return sendJson(res, 500, { error: '서버 오류: ' + e.message });
  }
});

server.listen(PORT, () => {
  console.log(`listening on :${PORT} (RP_ID=${RP_ID}, ORIGIN=${ORIGIN})`);
});
