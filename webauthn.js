'use strict';
// Minimal hand-written WebAuthn relying-party logic.
// No @simplewebauthn/* package: the npm registry is blocked for this
// session, so this uses only Node's built-in `crypto` plus a small CBOR
// decoder written for exactly the two shapes WebAuthn needs
// (attestationObject, COSE_Key). See README for why.

const crypto = require('crypto');

// ---------- base64url (Node's Buffer has native base64url support) ----------
const b64u = {
  encode: (buf) => Buffer.from(buf).toString('base64url'),
  decode: (str) => Buffer.from(str, 'base64url'),
};

// ---------- minimal CBOR decoder (major types 0,1,2,3,4,5,6,7) ----------
function cborDecode(buf, offset = 0) {
  const [value, next] = decodeItem(buf, offset);
  return { value, offset: next };
}

function decodeItem(buf, offset) {
  const initial = buf[offset];
  const majorType = initial >> 5;
  const additional = initial & 0x1f;
  offset += 1;

  let length;
  if (additional < 24) {
    length = additional;
  } else if (additional === 24) {
    length = buf.readUInt8(offset); offset += 1;
  } else if (additional === 25) {
    length = buf.readUInt16BE(offset); offset += 2;
  } else if (additional === 26) {
    length = buf.readUInt32BE(offset); offset += 4;
  } else if (additional === 27) {
    length = Number(buf.readBigUInt64BE(offset)); offset += 8;
  } else if (additional === 31) {
    length = null; // indefinite length — not expected in WebAuthn payloads
  } else {
    throw new Error('CBOR: 예약된 additional info 값');
  }

  switch (majorType) {
    case 0: // unsigned int
      return [length, offset];
    case 1: // negative int
      return [-1 - length, offset];
    case 2: { // byte string
      const val = buf.subarray(offset, offset + length);
      return [val, offset + length];
    }
    case 3: { // text string
      const val = buf.toString('utf8', offset, offset + length);
      return [val, offset + length];
    }
    case 4: { // array
      const arr = [];
      for (let i = 0; i < length; i++) {
        const [v, next] = decodeItem(buf, offset);
        arr.push(v); offset = next;
      }
      return [arr, offset];
    }
    case 5: { // map
      const map = new Map();
      for (let i = 0; i < length; i++) {
        const [k, next1] = decodeItem(buf, offset);
        const [v, next2] = decodeItem(buf, next1);
        map.set(k, v); offset = next2;
      }
      return [map, offset];
    }
    case 6: { // tag — decode and discard tag number, return tagged value
      const [v, next] = decodeItem(buf, offset);
      return [v, next];
    }
    case 7: // simple/float/bool/null
      if (additional === 20) return [false, offset];
      if (additional === 21) return [true, offset];
      if (additional === 22) return [null, offset];
      throw new Error('CBOR: 지원하지 않는 simple/float 타입');
    default:
      throw new Error('CBOR: 알 수 없는 major type');
  }
}

// ---------- COSE key (EC2 / RSA) -> Node JWK ----------
// COSE key map keys (as small ints per RFC 9053):
// 1=kty, 3=alg, -1=crv/n, -2=x/e, -3=y/d
function coseKeyToJwk(coseMap) {
  const kty = coseMap.get(1);
  if (kty === 2) {
    // EC2
    const crvId = coseMap.get(-1);
    const x = coseMap.get(-2);
    const y = coseMap.get(-3);
    const crv = crvId === 1 ? 'P-256' : crvId === 2 ? 'P-384' : crvId === 3 ? 'P-521' : null;
    if (!crv) throw new Error('지원하지 않는 EC 곡선');
    return { kty: 'EC', crv, x: b64u.encode(x), y: b64u.encode(y) };
  } else if (kty === 3) {
    // RSA
    const n = coseMap.get(-1);
    const e = coseMap.get(-2);
    return { kty: 'RSA', n: b64u.encode(n), e: b64u.encode(e) };
  }
  throw new Error('지원하지 않는 키 타입 (kty=' + kty + ')');
}

function verifySignature(jwk, alg, signedData, signature) {
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const hashAlg = alg === -257 ? 'RSA-SHA256' : 'sha256'; // -7 ES256, -257 RS256
  return crypto.verify(hashAlg, signedData, publicKey, signature);
}

// ---------- authenticatorData parsing ----------
function parseAuthData(authData) {
  const rpIdHash = authData.subarray(0, 32);
  const flagsByte = authData[32];
  const flags = {
    up: !!(flagsByte & 0x01),
    uv: !!(flagsByte & 0x04),
    at: !!(flagsByte & 0x40), // attested credential data present
    ed: !!(flagsByte & 0x80), // extension data present
  };
  const counter = authData.readUInt32BE(33);
  let rest = authData.subarray(37);

  let credentialId = null;
  let coseKeyMap = null;
  if (flags.at) {
    // aaguid(16) + credIdLen(2) + credId + COSE key (CBOR, remaining consumed length known)
    const credIdLen = rest.readUInt16BE(16);
    credentialId = rest.subarray(18, 18 + credIdLen);
    const keyStart = 18 + credIdLen;
    const decoded = cborDecode(rest, keyStart);
    coseKeyMap = decoded.value;
    rest = rest.subarray(decoded.offset);
  }

  return { rpIdHash, flags, counter, credentialId, coseKeyMap };
}

// ---------- options builders ----------
function randomChallenge() {
  return crypto.randomBytes(32);
}

function buildRegistrationOptions({ rpID, rpName, userHandle, username, excludeCredentials }) {
  const challenge = randomChallenge();
  return {
    optionsForClient: {
      rp: { id: rpID, name: rpName },
      user: { id: b64u.encode(userHandle), name: username, displayName: username },
      challenge: b64u.encode(challenge),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      timeout: 60000,
      attestation: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      excludeCredentials: (excludeCredentials || []).map((c) => ({
        type: 'public-key',
        id: c.credential_id,
      })),
    },
    challenge,
  };
}

function buildAuthenticationOptions({ rpID, allowCredentials }) {
  const challenge = randomChallenge();
  return {
    optionsForClient: {
      challenge: b64u.encode(challenge),
      timeout: 60000,
      rpId: rpID,
      userVerification: 'preferred',
      allowCredentials: (allowCredentials || []).map((c) => ({
        type: 'public-key',
        id: c.credential_id,
      })),
    },
    challenge,
  };
}

// ---------- verify registration ----------
function verifyRegistration({ credential, expectedChallenge, expectedOrigin, expectedRPID }) {
  const clientDataJSON = b64u.decode(credential.response.clientDataJSON);
  const clientData = JSON.parse(clientDataJSON.toString('utf8'));

  if (clientData.type !== 'webauthn.create') {
    throw new VerifyError('클라이언트 데이터 type이 webauthn.create가 아닙니다');
  }
  if (!timingSafeEqualStr(clientData.challenge, b64u.encode(expectedChallenge))) {
    throw new VerifyError('challenge가 일치하지 않습니다 (재사용되었거나 위조됨)');
  }
  if (clientData.origin !== expectedOrigin) {
    throw new VerifyError(`origin이 일치하지 않습니다 (받은 값: ${clientData.origin})`);
  }

  const attestationObject = b64u.decode(credential.response.attestationObject);
  const { value: attStmtMap } = cborDecode(attestationObject);
  const authData = attStmtMap.get('authData');
  const parsed = parseAuthData(authData);

  const expectedRpIdHash = crypto.createHash('sha256').update(expectedRPID).digest();
  if (!parsed.rpIdHash.equals(expectedRpIdHash)) {
    throw new VerifyError('rpIdHash가 일치하지 않습니다');
  }
  if (!parsed.flags.up) {
    throw new VerifyError('사용자 존재(UP) 플래그가 없습니다');
  }
  if (!parsed.coseKeyMap || !parsed.credentialId) {
    throw new VerifyError('공개키(attested credential data)가 없습니다');
  }

  const jwk = coseKeyToJwk(parsed.coseKeyMap);
  return {
    credentialId: b64u.encode(parsed.credentialId),
    publicKeyJwk: jwk,
    signCount: parsed.counter,
  };
}

// ---------- verify authentication ----------
function verifyAuthentication({ credential, expectedChallenge, expectedOrigin, expectedRPID, storedPublicKeyJwk, storedSignCount, alg }) {
  const clientDataJSON = b64u.decode(credential.response.clientDataJSON);
  const clientData = JSON.parse(clientDataJSON.toString('utf8'));

  if (clientData.type !== 'webauthn.get') {
    throw new VerifyError('클라이언트 데이터 type이 webauthn.get이 아닙니다');
  }
  if (!timingSafeEqualStr(clientData.challenge, b64u.encode(expectedChallenge))) {
    throw new VerifyError('challenge가 일치하지 않습니다 (이미 사용되었거나 만료됨)');
  }
  if (clientData.origin !== expectedOrigin) {
    throw new VerifyError(`origin이 일치하지 않습니다 (받은 값: ${clientData.origin})`);
  }

  const authData = b64u.decode(credential.response.authenticatorData);
  const rpIdHash = authData.subarray(0, 32);
  const flagsByte = authData[32];
  const up = !!(flagsByte & 0x01);
  const counter = authData.readUInt32BE(33);

  const expectedRpIdHash = crypto.createHash('sha256').update(expectedRPID).digest();
  if (!rpIdHash.equals(expectedRpIdHash)) {
    throw new VerifyError('rpIdHash가 일치하지 않습니다');
  }
  if (!up) {
    throw new VerifyError('사용자 존재(UP) 플래그가 없습니다');
  }
  if (storedSignCount > 0 && counter > 0 && counter <= storedSignCount) {
    throw new VerifyError('서명 카운터가 증가하지 않았습니다 (복제된 인증기 의심)');
  }

  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
  const signedData = Buffer.concat([authData, clientDataHash]);
  const signature = b64u.decode(credential.response.signature);

  const ok = verifySignature(storedPublicKeyJwk, alg, signedData, signature);
  if (!ok) {
    throw new VerifyError('서명 검증에 실패했습니다');
  }
  return { newSignCount: counter };
}

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

class VerifyError extends Error {}

module.exports = {
  b64u,
  cborDecode,
  buildRegistrationOptions,
  buildAuthenticationOptions,
  verifyRegistration,
  verifyAuthentication,
  VerifyError,
  randomChallenge,
};
