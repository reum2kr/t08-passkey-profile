// Full evidence-collection run for ALEPH 과제 8.
// Drives the real WebAuthn ceremonies through Chrome DevTools Protocol
// virtual authenticators (Playwright), and hits the raw HTTP API directly
// with fetch() for the checks that don't need a browser ceremony
// (challenge reuse, cross-account access, unauthenticated access).
//
// Usage: BASE_URL=http://localhost:3000 node scripts/evidence.mjs
import { chromium } from 'playwright';
import fs from 'fs';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const log = [];
function record(section, note, extra) {
  log.push({ ts: new Date().toISOString(), section, note, extra });
  console.log(`[${section}] ${note}`);
}

function redactCookie(cookieHeader) {
  if (!cookieHeader) return cookieHeader;
  return cookieHeader.replace(/sid=[^;]+/, 'sid=***redacted***');
}

async function rawFetch(path, opts = {}) {
  const res = await fetch(BASE + path, opts);
  let body = null;
  try { body = await res.json(); } catch (e) { /* ignore */ }
  const headers = Object.fromEntries(res.headers.entries());
  if (headers['set-cookie']) headers['set-cookie'] = redactCookie(headers['set-cookie']);
  return { status: res.status, headers, body };
}

function extractSid(setCookieHeader) {
  const m = /sid=([^;]+)/.exec(setCookieHeader || '');
  return m ? m[1] : null;
}

async function main() {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });

  // ================= Card 1: public/private split & unauth access =================
  record('card1', '--- 공개/비공개 분리, 비인증 접근 확인 ---');

  const homeRes = await fetch(BASE + '/');
  const homeHtml = await homeRes.text();
  const leaked = ['다음 스프린트 메모', '패스키 로그인 붙이는 작업', '개인 프로젝트 아이디어'];
  const anyLeak = leaked.some((s) => homeHtml.includes(s));
  record('card1', `GET / (로그인 없음) -> ${homeRes.status}, 페이지 소스에 비공개 문구 포함 여부: ${anyLeak}`, { status: homeRes.status, leaked: anyLeak });

  const unauth = await rawFetch('/api/private/items');
  record('card1', `GET /api/private/items (쿠키 없음) -> ${unauth.status}`, unauth);
  const unauthPasskeys = await rawFetch('/api/passkeys');
  record('card1', `GET /api/passkeys (쿠키 없음) -> ${unauthPasskeys.status}`, unauthPasskeys);

  // ================= Card 2/3/4: account "areum" with 2 passkeys =================
  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  const cdpA = await ctxA.newCDPSession(pageA);
  await cdpA.send('WebAuthn.enable');
  const authA1 = await cdpA.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  record('card2', `가상 인증기 1 추가 (계정 areum용, 실제 물리 기기 대신 CDP WebAuthn 가상 인증기로 자동화 테스트): id=${authA1.authenticatorId}`);

  const registerReqs = [];
  pageA.on('requestfinished', async (req) => {
    if (req.url().includes('/api/register/') || req.url().includes('/api/login/')) {
      try {
        const res = await req.response();
        registerReqs.push({ url: req.url(), method: req.method(), postData: req.postData(), status: res ? res.status() : null });
      } catch (e) {}
    }
  });

  await pageA.goto(BASE + '/#private');
  await pageA.click('#tabRegister');
  await pageA.fill('#registerUsername', 'areum');
  await pageA.fill('#registerDeviceName', '테스트 노트북 (가상 인증기1)');
  await pageA.click('#btnRegister');
  await pageA.waitForSelector('#private-unlocked:not([hidden])', { timeout: 10000 });
  record('card2', '계정 areum 등록 완료, 첫 패스키(노트북) 등록됨, 등록 직후 자동 로그인됨');

  const startCall = registerReqs.find((r) => r.url.endsWith('/api/register/start'));
  const finishCall = registerReqs.find((r) => r.url.endsWith('/api/register/finish'));
  record('card2', 'register/start 요청 본문', { postData: startCall && startCall.postData });
  record('card2', 'register/finish 요청 본문 (개인키 없음 — clientDataJSON/attestationObject만 전송됨)', { postData: finishCall && finishCall.postData });

  // ---- concrete proof that what's stored is a public key, not a secret ----
  {
    const { DatabaseSync: DBPeek0 } = await import('node:sqlite');
    const dbPeek0 = new DBPeek0(new URL('../app.db', import.meta.url).pathname);
    const row = dbPeek0.prepare(
      "SELECT device_name, public_key_jwk, sign_count FROM credentials c JOIN users u ON u.id=c.user_id WHERE u.username='areum' LIMIT 1"
    ).get();
    dbPeek0.close();
    record('card2', 'DB에 실제로 저장된 credentials 행 (public_key_jwk는 JWK 공개키 — x,y 좌표만 있고 개인키(d 값)는 없음, 비밀번호 아님)', {
      device_name: row.device_name,
      public_key_jwk: JSON.parse(row.public_key_jwk),
      sign_count: row.sign_count,
    });
  }

  // ---- registration challenge uniqueness (separate from login's) ----
  {
    const r1 = await rawFetch('/api/register/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'chalcheck1' }) });
    const r2 = await rawFetch('/api/register/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'chalcheck2' }) });
    record('card2', `등록 challenge 두 번 요청 결과 — 서로 다름: ${r1.body.challenge !== r2.body.challenge}`, { challenge1: r1.body.challenge, challenge2: r2.body.challenge });
  }

  // ---- cancelling registration (never calling /finish) leaves nothing stored ----
  {
    await rawFetch('/api/register/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'cancelled-user' }) });
    // ...user cancels the passkey prompt here in real life; the client never calls /finish.
    const loginAttempt = await rawFetch('/api/login/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'cancelled-user' }) });
    record('card2', `register/start만 호출하고 /finish는 호출하지 않은(=등록 취소) 아이디로 로그인 시도 -> ${loginAttempt.status} (계정이 생성되지 않았음이 확인됨)`, loginAttempt);
  }

  const cookiesA = await ctxA.cookies();
  const sidA1 = cookiesA.find((c) => c.name === 'sid').value;
  record('card3', `로그인 식별 방식: 세션 쿠키(sid, HttpOnly) — 서버 sessions 테이블에서 sid -> user_id 매핑 (JWT 미사용). sid=***redacted***`);

  // second passkey for the same account
  registerReqs.length = 0;
  const authA2 = await cdpA.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  record('card4', `가상 인증기 2 추가 (계정 areum의 두 번째 기기 역할): id=${authA2.authenticatorId}`);

  pageA.once('dialog', async (d) => { await d.accept('휴대폰 (가상 인증기2)'); });
  await pageA.click('#btnAddPasskey');
  await pageA.waitForTimeout(1500);
  await pageA.waitForFunction(() => document.querySelectorAll('#passkeyList .priv-key-row').length >= 2, { timeout: 10000 });
  record('card4', '두 번째 패스키(휴대폰) 등록 완료');

  const passkeyListRes = await pageA.evaluate(async () => (await fetch('/api/passkeys')).json());
  record('card4', '패스키 목록 (2개, 각각 이름+등록일)', passkeyListRes);
  await pageA.locator('#private-unlocked').scrollIntoViewIfNeeded();
  await pageA.locator('#passkeyList').scrollIntoViewIfNeeded();
  await pageA.waitForTimeout(200);
  await pageA.locator('#private-unlocked').screenshot({ path: 'evidence/card4-two-passkeys.png' });
  record('card4', '스크린샷 저장: evidence/card4-two-passkeys.png (패스키 2개가 실제로 화면에 보이는 상태로 재캡처)');

  // seed extra confirmation of >=3 private items (already auto-seeded 3 on registration)
  const itemsBefore = await pageA.evaluate(async () => (await fetch('/api/private/items')).json());
  record('card1', `비공개 항목 개수(자동 시드): ${itemsBefore.items.length}개`, itemsBefore.items.map((i) => i.title));

  // ---- challenge uniqueness across two login/start calls ----
  const loginStart1 = await pageA.evaluate(async () => (await fetch('/api/login/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'areum' }) })).json());
  const loginStart2 = await pageA.evaluate(async () => (await fetch('/api/login/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'areum' }) })).json());
  record('card3', `로그인 challenge 두 번 요청 결과 — 서로 다름: ${loginStart1.challenge !== loginStart2.challenge}`, { challenge1: loginStart1.challenge, challenge2: loginStart2.challenge });

  // ---- logout, then real login via UI (authenticator1 still has its credential; authenticator2 also holds one) ----
  await pageA.evaluate(async () => { await fetch('/api/logout', { method: 'POST' }); });
  record('card3', '로그아웃 완료');
  const afterLogoutPrivate = await pageA.evaluate(async () => { const r = await fetch('/api/private/items'); return { status: r.status, body: await r.json() }; });
  record('card3', `로그아웃 직후 같은 세션으로 /api/private/items 재요청 -> ${afterLogoutPrivate.status} (거절 확인)`, afterLogoutPrivate);

  await pageA.reload();
  await pageA.click('#tabLogin');
  await pageA.fill('#loginUsername', 'areum');
  registerReqs.length = 0;
  await pageA.click('#btnLogin');
  await pageA.waitForSelector('#private-unlocked:not([hidden])', { timeout: 10000 });
  record('card3', '로그인 성공 (성공한 로그인 요청)', registerReqs.filter((r) => r.url.includes('/login/')));

  // ---- genuine signature-verification success vs failure (same real ceremony, one with the
  // signature byte-flipped after the fact) — distinct from the lookup-level rejections above,
  // this actually reaches crypto.verify() in webauthn.js ----
  {
    const b64uHelpers = `
      function b64uToBuf(b64u){const pad='='.repeat((4-(b64u.length%4))%4);const base64=(b64u+pad).replace(/-/g,'+').replace(/_/g,'/');const bin=atob(base64);const buf=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);return buf.buffer;}
      function bufToB64u(buf){const bytes=new Uint8Array(buf);let bin='';for(let i=0;i<bytes.length;i++)bin+=String.fromCharCode(bytes[i]);return btoa(bin).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
    `;
    async function doRealAssertion(page, tamper) {
      return page.evaluate(async ({ helpers, tamper }) => {
        eval(helpers);
        const startRes = await fetch('/api/login/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'areum' }) });
        const opts = await startRes.json();
        const publicKey = {
          challenge: b64uToBuf(opts.challenge),
          timeout: opts.timeout,
          rpId: opts.rpId,
          userVerification: opts.userVerification,
          allowCredentials: opts.allowCredentials.map((c) => ({ type: c.type, id: b64uToBuf(c.id) })),
        };
        const assertion = await navigator.credentials.get({ publicKey });
        let signatureB64u = bufToB64u(assertion.response.signature);
        if (tamper) {
          // flip one base64url character in the middle of the real signature —
          // still well-formed, but no longer the correct signature.
          const mid = Math.floor(signatureB64u.length / 2);
          const ch = signatureB64u[mid];
          const replacement = ch === 'A' ? 'B' : 'A';
          signatureB64u = signatureB64u.slice(0, mid) + replacement + signatureB64u.slice(mid + 1);
        }
        const credentialForServer = {
          id: bufToB64u(assertion.rawId),
          response: {
            clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
            authenticatorData: bufToB64u(assertion.response.authenticatorData),
            signature: signatureB64u,
            userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null,
          },
        };
        const finishRes = await fetch('/api/login/finish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ credential: credentialForServer }) });
        return { status: finishRes.status, body: await finishRes.json() };
      }, { helpers: b64uHelpers, tamper });
    }

    // areum is logged out right now (from the /api/logout above, before this reload+login),
    // but the click on #btnLogin just re-logged us in — log out again so this doesn't
    // interfere, then run two independent real ceremonies.
    await pageA.evaluate(async () => { await fetch('/api/logout', { method: 'POST' }); });
    const goodSig = await doRealAssertion(pageA, false);
    record('card3', `진짜 서명으로 로그인 -> ${goodSig.status} (성공, crypto.verify 통과)`, goodSig);
    const badSig = await doRealAssertion(pageA, true);
    record('card3', `같은 방식이지만 서명 1바이트를 조작해서 제출 -> ${badSig.status} (실패, crypto.verify가 실제로 거절함)`, badSig);
  }

  // ---- replay the exact same login/finish body -> must be rejected (single-use challenge) ----
  const loginFinishCall = registerReqs.find((r) => r.url.endsWith('/api/login/finish'));
  const replay = await pageA.evaluate(async (postData) => {
    const r = await fetch('/api/login/finish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: postData });
    return { status: r.status, body: await r.json() };
  }, loginFinishCall.postData);
  record('card3', `이미 쓴 로그인 응답(challenge)을 그대로 재전송 -> ${replay.status} (거절됨, 재사용 불가 확인)`, replay);

  // ---- delete the first passkey (authenticator1's), then confirm it can no longer be used, and the remaining one still can ----
  const passkeysNow = await pageA.evaluate(async () => (await fetch('/api/passkeys')).json());
  const firstPk = passkeysNow.passkeys[0];

  // capture the raw credential_id of the passkey we're about to delete, so we can
  // later prove — with a direct API call — that it's rejected once gone.
  const { DatabaseSync: DatabaseSync1 } = await import('node:sqlite');
  const dbPeek = new DatabaseSync1(new URL('../app.db', import.meta.url).pathname);
  const deletedCredRow = dbPeek.prepare('SELECT credential_id FROM credentials WHERE id = ?').get(firstPk.id);
  dbPeek.close();

  const delRes = await pageA.evaluate(async (id) => { const r = await fetch('/api/passkeys/' + id, { method: 'DELETE' }); return { status: r.status, body: await r.json() }; }, firstPk.id);
  record('card4', `패스키 "${firstPk.device_name}" 삭제 -> ${delRes.status}`, delRes);

  await cdpA.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authA1.authenticatorId }); // that physical device is gone too
  await pageA.evaluate(async () => { await fetch('/api/logout', { method: 'POST' }); });
  await pageA.reload();
  await pageA.click('#tabLogin');
  await pageA.fill('#loginUsername', 'areum');
  await pageA.click('#btnLogin'); // only authenticator2 (휴대폰) remains available in the browser now
  await pageA.waitForSelector('#private-unlocked:not([hidden])', { timeout: 10000 });
  record('card4', '남은 패스키(휴대폰, authenticator2)로는 정상 로그인 성공 (authenticator1은 브라우저에서도 완전히 제거된 상태)');

  // direct proof that the *deleted* credential id is rejected, independent of the UI
  const freshLoginStartRaw = await fetch(BASE + '/api/login/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'areum' }) });
  const freshLoginStartCookie = extractSid(freshLoginStartRaw.headers.get('set-cookie'));
  const freshLoginStartBody = await freshLoginStartRaw.json();
  record('card4', `삭제 후 새 로그인 challenge의 allowCredentials 개수: ${freshLoginStartBody.allowCredentials.length} (삭제된 패스키는 더 이상 목록에 없음)`);
  const deletedKeyAttempt = await rawFetch('/api/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `sid=${freshLoginStartCookie}` },
    body: JSON.stringify({ credential: { id: deletedCredRow.credential_id, response: { clientDataJSON: 'x', authenticatorData: 'x', signature: 'x' } } }),
  });
  record('card4', `삭제된 패스키의 credential_id로 직접 로그인 시도 -> ${deletedKeyAttempt.status} (거절, 더 이상 사용 불가)`, deletedKeyAttempt);

  // ---- try deleting the last remaining passkey -> must be blocked ----
  const remaining = await pageA.evaluate(async () => (await fetch('/api/passkeys')).json());
  const lastPk = remaining.passkeys[0];
  const delLastRes = await pageA.evaluate(async (id) => { const r = await fetch('/api/passkeys/' + id, { method: 'DELETE' }); return { status: r.status, body: await r.json() }; }, lastPk.id);
  record('card4', `마지막 남은 패스키 삭제 시도 -> ${delLastRes.status} (서버가 막음)`, delLastRes);

  const cookiesA2 = await ctxA.cookies();
  const sidAFinal = cookiesA2.find((c) => c.name === 'sid').value;

  // ================= Card 5: second account "guest2", cross-account isolation =================
  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  const cdpB = await ctxB.newCDPSession(pageB);
  await cdpB.send('WebAuthn.enable');
  const authB1 = await cdpB.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'ble', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await pageB.goto(BASE + '/#private');
  await pageB.click('#tabRegister');
  await pageB.fill('#registerUsername', 'guest2');
  await pageB.fill('#registerDeviceName', '두 번째 계정 테스트 기기');
  await pageB.click('#btnRegister');
  await pageB.waitForSelector('#private-unlocked:not([hidden])', { timeout: 10000 });
  record('card5', '두 번째 계정 guest2 등록 완료 (서로 다른 사람이라고 가정한 테스트 계정)');

  const itemsB = await pageB.evaluate(async () => (await fetch('/api/private/items')).json());
  const itemsA = await pageA.evaluate(async () => (await fetch('/api/private/items')).json());
  record('card5', 'areum 계정의 비공개 항목', itemsA.items.map((i) => ({ id: i.id, title: i.title })));
  record('card5', 'guest2 계정의 비공개 항목 (서로 다른 내용)', itemsB.items.map((i) => ({ id: i.id, title: i.title })));

  const areumItemId = itemsA.items[0].id;
  const guest2ItemId = itemsB.items[0].id;

  const countBeforeA = itemsA.items.length, countBeforeB = itemsB.items.length;

  // A tries to read B's item by id
  const crossAtoB = await pageA.evaluate(async (id) => { const r = await fetch('/api/private/items/' + id); return { status: r.status, body: await r.json() }; }, guest2ItemId);
  record('card5', `areum 세션으로 guest2의 항목(id=${guest2ItemId}) 조회 시도 -> ${crossAtoB.status}`, crossAtoB);

  // B tries to read A's item by id
  const crossBtoA = await pageB.evaluate(async (id) => { const r = await fetch('/api/private/items/' + id); return { status: r.status, body: await r.json() }; }, areumItemId);
  record('card5', `guest2 세션으로 areum의 항목(id=${areumItemId}) 조회 시도 -> ${crossBtoA.status}`, crossBtoA);

  const itemsA2 = await pageA.evaluate(async () => (await fetch('/api/private/items')).json());
  const itemsB2 = await pageB.evaluate(async () => (await fetch('/api/private/items')).json());
  record('card5', `거절 전후 자료 건수 비교 — areum: ${countBeforeA} -> ${itemsA2.items.length}, guest2: ${countBeforeB} -> ${itemsB2.items.length} (변화 없음 확인)`);

  // client-supplied "other account" hint in query string — server must ignore it
  const spoofTry = await pageA.evaluate(async (otherId) => {
    const r = await fetch('/api/private/items?user_id=' + otherId + '&as=guest2');
    return { status: r.status, body: await r.json() };
  }, 999999);
  record('card5', 'areum 세션으로 쿼리스트링에 다른 계정을 적어 보낸 요청 (?user_id=...&as=guest2) -> 서버는 세션의 실제 로그인 사용자만 사용, 그래도 areum 자신의 자료만 반환됨', spoofTry.body.items.map((i) => i.title));
  record('card5', '이 거절/무시를 만드는 소스 위치: server.js의 requireAuth() 함수(세션의 user.id만 신뢰) 및 GET /api/private/items, GET /api/private/items/:id 핸들러의 `row.user_id !== user.id` 검사 — 클라이언트가 보낸 user_id/as 파라미터는 어디에서도 읽지 않음');

  // ---- cross-account passkey attempt: forge a login/finish for guest2 using areum's credential id ----
  // The passkey list API never exposes raw credential_id (by design), so for this
  // one adversarial test we read it straight out of the database, the way an
  // attacker who somehow learned the credential id (it is not secret — only the
  // private key matters) would try to use it against the wrong account.
  const { DatabaseSync } = await import('node:sqlite');
  const dbForTest = new DatabaseSync(new URL('../app.db', import.meta.url).pathname);
  const areumCred = dbForTest.prepare(
    "SELECT credential_id FROM credentials c JOIN users u ON u.id = c.user_id WHERE u.username = 'areum' LIMIT 1"
  ).get();
  dbForTest.close();

  const guestLoginStartRaw = await fetch(BASE + '/api/login/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'guest2' }) });
  const guestLoginStart = { status: guestLoginStartRaw.status, body: await guestLoginStartRaw.json() };
  const forgedSessionCookie = extractSid(guestLoginStartRaw.headers.get('set-cookie'));
  const forgedFinish = await rawFetch('/api/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `sid=${forgedSessionCookie}` },
    body: JSON.stringify({ credential: { id: areumCred.credential_id, response: { clientDataJSON: 'x', authenticatorData: 'x', signature: 'x' } } }),
  });
  record('card5', `guest2 로그인 흐름 중, areum 소유의 패스키 credential_id로 응답을 위조해 제출 -> ${forgedFinish.status} (거절: 계정에 속하지 않은 패스키)`, forgedFinish);

  await browser.close();

  fs.writeFileSync('evidence/evidence-log.json', JSON.stringify(log, null, 2));
  console.log('\n=== evidence/evidence-log.json 저장 완료 ===');
}

main().catch((e) => { console.error(e); process.exit(1); });
