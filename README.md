# 과제 8 — 내 소개 페이지에 패스키 달기

## 제출물

- **공개 결과물 주소**: https://t08-passkey-profile.onrender.com
- **소스 주소**: https://github.com/reum2kr/t08-passkey-profile
- 아래 "인증 구현 설명서", "짧은 확인 방법", "AI와 내 판단"이 이 문서 안에 모두 들어 있습니다.
- 요청/응답 원본 로그: [`evidence/evidence-log.json`](evidence/evidence-log.json)
- 스크린샷: [`evidence/card4-two-passkeys.png`](evidence/card4-two-passkeys.png)(패스키 2개 등록, 로컬 테스트), [`evidence/live-render-verified.png`](evidence/live-render-verified.png)(실제 배포 주소에서 계정 등록·패스키 등록·비공개 메모까지 직접 확인)
- 제출물 어디에도 실제 개인정보는 없습니다. 비공개 영역에 들어 있는 메모(스프린트 메모, 지원 후보 목록, 회고, 프로젝트 아이디어 등)는 전부 만들어 넣은 가상의 내용이며, 항목마다 "(가상)"이라고 표시했습니다.

---

## 인증 구현 설명서

### ① 무엇으로 붙였나

**직접 구현**했습니다. 라이브러리나 외부 인증 서비스(Auth0, Firebase Auth 등)를 쓰지 않았습니다.

- 서버: Node.js 내장 모듈만 사용 — `http`(라우팅), `crypto`(챌린지 생성·서명 검증·해시), `node:sqlite`(저장소).
- WebAuthn 로직(`webauthn.js`): CBOR 디코더, COSE 키 → JWK 변환, attestationObject/authenticatorData 파싱, 서명 검증을 전부 직접 작성했습니다.
- 프런트: `navigator.credentials.create()` / `navigator.credentials.get()` 브라우저 내장 WebAuthn API를 직접 호출했습니다(`public/app.js`). base64url ↔ ArrayBuffer 변환도 직접 작성한 30줄짜리 헬퍼입니다.

### ② 왜 그걸 골랐나

원래는 `@simplewebauthn/server`·`@simplewebauthn/browser`(라이브러리)와 PostgreSQL을 쓸 계획이었습니다(6·7번 과제와 같은 조합). 하지만 이번 과제를 만든 개발 세션에서 **npm 레지스트리(registry.npmjs.org) 접근이 조직 정책으로 막혀 있어**(`403 host_not_allowed`) 어떤 npm 패키지도 새로 설치할 수 없었습니다. `pg`도, `@simplewebauthn/*`도, `express`조차 설치가 안 됐습니다.

그래서 선택지는 둘 중 하나였습니다: (a) 막힌 레지스트리를 우회하려고 시도한다, (b) Node.js에 이미 내장된 것만으로 만든다. 우회는 프록시 안내문서에도 "재시도하거나 우회하지 말고 보고하라"고 되어 있어 하지 않았고, 대신 Node 22에 내장된 `node:sqlite`(DB), `crypto`(서명 검증), `Buffer`의 `base64url` 인코딩, 브라우저 내장 WebAuthn API만으로 전부 구현했습니다. 결과적으로 외부 의존성이 0개인 서버가 되었고, "비밀번호 대신 무엇이 그 자리를 채우는가"를 라이브러리 뒤에 숨기지 않고 직접 볼 수 있어서 이번 과제 취지에는 오히려 더 맞았다고 생각합니다.

PostgreSQL 대신 SQLite를 쓴 것도 같은 이유입니다(`pg` 설치 불가). 자세한 트레이드오프는 ⑥에 적었습니다.

### ③ 어디를 어떻게 고쳤나

1번 과제의 `index.html`(GitHub Pages, 정적 사이트)은 서버를 돌릴 수 없어서, 그 파일을 그대로 가져와 `public/index.html`로 옮기고 맨 아래에 `<section id="private">`(비공개 영역)만 새로 추가했습니다. 1번의 공개 섹션(ABOUT/JOURNEY/WORK/SKILLS/CONTACT)은 한 글자도 지우지 않았습니다.

네 흐름이 지나는 위치(전부 `server.js` 한 파일, 파일 최상단부터 순서대로):

| 흐름 | 엔드포인트 | 위치 |
|---|---|---|
| 등록 | `POST /api/register/start`, `POST /api/register/finish` | `server.js` "registration: start/finish" 섹션, `webauthn.js`의 `buildRegistrationOptions`/`verifyRegistration` |
| 로그인 | `POST /api/login/start`, `POST /api/login/finish` | `server.js` "login: start/finish" 섹션, `webauthn.js`의 `buildAuthenticationOptions`/`verifyAuthentication` |
| 로그아웃 | `POST /api/logout` | `server.js` "logout" 섹션 — 세션의 `userId`만 `null`로 비움 |
| 비공개 자료 조회 | `GET /api/private/items`, `GET /api/private/items/:id`, `GET /api/passkeys` | `server.js` "private items" / "passkeys" 섹션, 전부 `requireAuth()` 통과 후에만 실행 |

프런트 로직은 `public/app.js` 하나에, 스타일은 `public/index.html` 안 `#private` 섹션에 인라인 `<style>`로 넣어 기존 스타일시트를 건드리지 않았습니다.

### ④ 안 열리는 것을 확인한 기록

전체 원본 로그는 `evidence/evidence-log.json`에 있습니다. 네 가지 확인 각각 성공/실패(또는 거절) 요청을 나란히 남겼습니다.

**1) 로그인 없이 열기**
```
[거절] GET /api/private/items (쿠키 없음) -> 401 {"error":"로그인이 필요합니다 (패스키로 인증되지 않음)"}
[거절] GET /api/passkeys       (쿠키 없음) -> 401 (동일)
       GET /  (쿠키 없음) -> 200, 그러나 페이지 소스에 비공개 문구("다음 스프린트 메모" 등) 없음 확인
[성공] 같은 패스키로 로그인한 뒤 GET /api/private/items -> 200, 항목 3개 정상 반환 (아래 3번 항목의 로그인 성공 참고)
```

**2) 남의 패스키로 열기**
```
[거절] guest2 로그인 흐름 중, areum 소유의 credential_id로 응답을 위조해 제출
       POST /api/login/finish -> 400 "해당 계정에 속하지 않은 패스키입니다"
[성공] (대조군) areum 본인의 credential_id로 진짜 서명까지 만들어 제출 -> 200 (아래 서명 검증 항목)

[거절] areum 세션으로 guest2의 항목(id=4) 직접 조회 -> GET /api/private/items/4 -> 403 "다른 계정의 자료입니다"
[거절] guest2 세션으로 areum의 항목(id=1) 직접 조회 -> GET /api/private/items/1 -> 403 (동일)
[성공] (대조군) areum 세션으로 areum 자신의 항목(id=1) 조회 -> GET /api/private/items/1 -> 200
       거절 전후 자료 건수: areum 3->3, guest2 3->3 (변화 없음)
```

서명 검증 자체가 진짜로 동작하는지도 별도로 확인했습니다 — 위조된 credential_id(위 항목)는 사실 DB 조회 단계에서 걸러지는 것이라, **서명 검증(`crypto.verify`) 자체**가 살아있는지는 다른 테스트로 증명했습니다: 진짜 기기로 진짜 서명을 만든 뒤, 그 서명 값의 문자 하나만 바꿔서 제출.
```
[성공] 진짜 서명 그대로 제출 -> POST /api/login/finish -> 200
[거절] 같은 서명에서 한 글자만 조작해서 제출 -> POST /api/login/finish -> 401 "서명 검증에 실패했습니다"
```

**3) 이미 쓴 질문(challenge) 재사용**
```
[성공] 로그인 성공: POST /api/login/finish -> 200 {"ok":true,"username":"areum"}
[거절] 같은 요청 본문을 그대로 재전송: POST /api/login/finish -> 400 "로그인 요청이 없거나 이미 처리(또는 만료)되었습니다"
```
등록 쪽 challenge도 매 요청 다른 값이 나오는 것을 별도로 확인했습니다: 서로 다른 아이디로 `register/start`를 두 번 호출 → challenge 값이 서로 다름을 확인.

등록을 취소했을 때(=`/finish`를 끝까지 부르지 않았을 때) 정말 아무것도 안 남는지도 확인했습니다:
```
POST /api/register/start {username: "cancelled-user"} 만 호출하고 /finish는 호출하지 않음(=사람이 패스키 창을 취소한 상황)
그 아이디로 로그인 시도: POST /api/login/start -> 404 "해당 아이디가 없습니다" (계정이 아예 생성되지 않았음)
```

**4) 패스키 삭제 뒤 로그인**
```
패스키 "테스트 노트북" 삭제: DELETE /api/passkeys/1 -> 200
그 패스키가 물려 있던 기기(가상 인증기)를 브라우저에서도 완전히 제거
[성공] 로그인 재시도 -> 200 (남은 패스키 "휴대폰"으로 성공)
[거절] 삭제된 패스키의 credential_id로 직접 로그인 시도 -> 400 "해당 계정에 속하지 않은 패스키입니다" (더 이상 사용 불가)
[거절] 마지막 남은 패스키 삭제 시도 -> 409 "마지막 남은 패스키는 삭제할 수 없습니다" (서버가 의도적으로 막음)
```

**저장된 값이 정말 "공개키"인지 직접 확인** — DB에서 실제로 credentials 테이블 한 행을 그대로 꺼내봤습니다:
```json
{
  "device_name": "테스트 노트북 (가상 인증기1)",
  "public_key_jwk": { "kty": "EC", "crv": "P-256",
    "x": "paKuBz7k3oek2ZkCxphhoE3OBRXJWCY1lmH7BwK9Rhk",
    "y": "np5rKVuC7Ktp58DyNPYRn2aY_hWA9dvyc5_-_YruQAo" },
  "sign_count": 1
}
```
`x`, `y`는 타원곡선 공개키의 좌표일 뿐이고, 이 값만으로는 로그인할 수 없습니다(서명은 개인키로만 만들 수 있음). 개인키에 해당하는 `d` 값은 어디에도 없고, 등록 요청 본문(위 ②)에도 개인키 필드가 없습니다 — 등록 과정 내내 개인키가 기기 밖으로 나간 적이 없다는 뜻입니다.

**패스키 저장 위치**: 자동화 테스트는 실제 물리 보안키 대신 Chrome DevTools Protocol의 **WebAuthn 가상 인증기**(virtual authenticator)를 썼습니다 — 실제 ECDSA(P-256) 키 쌍 생성, 진짜 CBOR/서명 검증 경로를 그대로 통과하는 진짜 WebAuthn 세리모니이며, 클릭만 사람 대신 스크립트가 했습니다(`scripts/evidence.mjs`). 이 자동화 증거는 개발 중 localhost에서 수집했고(배포된 것과 완전히 동일한 서버 코드), **실제 배포 주소(onrender.com)에서도** 직접 브라우저로 계정 생성 → 패스키 등록 → 비공개 메모 확인까지 재현했습니다. 이때 등록 화면에서 패스키를 실제로 저장한 곳은 기기 자체(Windows Hello 등)가 아니라 **Chrome의 구글 비밀번호 관리자**(Google Password Manager, 구글 계정에 동기화되는 방식)였고, 그 증거를 [`evidence/live-render-verified.png`](evidence/live-render-verified.png)로 남겼습니다.

### ⑤ AI와 나

아래 "AI와 내 판단" 섹션과 같은 내용입니다.

### ⑥ 아직 못 막은 것

1. **SQLite 데이터가 영구 저장소가 아닙니다.** Render 무료 웹 서비스의 로컬 디스크는 영구 볼륨이 아니라서, 재배포하거나 인스턴스가 재시작되면 계정·패스키·비공개 메모가 전부 초기화됩니다. 원래 계획이던 PostgreSQL(Render의 영구 DB)을 쓰지 못한 대가입니다. 실제 서비스라면 Render의 유료 영구 디스크나 별도 관리형 DB가 필요합니다.
2. **로그인 시도에 속도 제한(rate limiting)이 없습니다.** `POST /api/login/start`에 존재하지 않는 아이디를 넣으면 404를 즉시 돌려주기 때문에, 무차별로 아이디를 넣어보면 어떤 아이디가 실제로 가입되어 있는지(계정 존재 여부, user enumeration) 추측할 수 있습니다. IP당 요청 횟수 제한이나 존재하지 않는 아이디에도 항상 같은 지연·같은 응답을 주는 처리가 아직 없습니다.

---

## 짧은 확인 방법

1. **어디로 가나요**: 공개 주소(`/`) 맨 아래 "PRIVATE SPACE" 섹션(또는 상단 네비게이션의 `PRIVATE` 링크)으로 이동합니다.
2. **세 단계 안에 무엇을 하나요**: (1) "계정 만들기" 탭에서 아이디와 기기 이름을 입력 → (2) "패스키 등록하고 시작하기" 클릭 → (3) 브라우저가 띄우는 패스키 등록창(지문/PIN/보안키 등)에서 승인.
3. **무엇이 보이면 통과인가요**: 승인 직후 자동으로 "안녕하세요, OO님" 화면으로 바뀌고 등록된 패스키 목록과 비공개 메모 3개 이상이 보이면 통과입니다. 이후 로그아웃 후 같은 아이디로 "로그인" 탭에서 패스키만으로 다시 들어갈 수 있어야 합니다.
4. **안 될 때는 무엇이 보이나요**: 패스키 창을 취소하면 빨간 글씨로 "등록이 취소되었거나 실패했습니다"가 뜨고 아무것도 저장되지 않습니다. 이미 있는 아이디로 등록하면 "이미 있는 아이디입니다"가, 등록되지 않은 아이디로 로그인하면 "해당 아이디가 없습니다"가 표시됩니다.

---

## AI와 내 판단

- **AI에게 맡긴 일**: WebAuthn 스펙에 맞는 CBOR 파서·COSE→JWK 변환·서명 검증 코드 작성, 세션/챌린지 저장 구조 설계, Chrome DevTools Protocol 가상 인증기를 이용한 자동 증거 수집 스크립트 작성.
- **내가 직접 판단한 일**: 마지막 남은 패스키는 삭제를 막을지(=계정이 영영 잠기는 걸 방지) 아니면 허용하고 경고만 할지 고민하다가, "비밀번호 같은 대체 수단이 아예 없는 구조"라는 점을 감안해 **서버에서 삭제를 막는 쪽**으로 정했습니다. 또 계정 생성 시 개인정보를 아예 요구하지 않고 아이디+기기이름만 받도록 범위를 좁혔습니다.
- **AI 제안을 따르지 않은 일**: 처음에는 이메일 인증이나 복구 코드(recovery code) 같은 계정 복구 수단을 추가하자는 방향으로 설계가 흘러가고 있었는데, 이번 과제의 핵심이 "비밀번호를 없애면 무엇이 그 자리를 채우는가"를 있는 그대로 보는 것이라 생각해서, 복구 수단을 넣지 않고 대신 "패스키 두 개를 등록해 두라"는 과제 지시를 그대로 유일한 대비책으로 남겨뒀습니다. 그래서 ⑥에 "패스키 전부 삭제 시 복구 불가"를 한계로 명시했습니다.

---

## 완주 체크리스트 (자체 점검)

- [x] 공개 영역과 비공개 영역을 화면에서 갈라 두었다 (`#private` 섹션, 상단에 "비공개 영역" 라벨)
- [x] 패스키를 등록했고, 서버에 저장된 것이 공개키라는 것을 보였다 (`credentials.public_key_jwk` 컬럼, JWK 형식)
- [x] 매번 새 질문이 오고, 이미 쓴 질문은 다시 통하지 않는 것을 확인했다
- [x] 패스키를 두 개 등록해 하나를 지운 뒤에도 들어갔다
- [x] 남의 패스키로는 열리지 않는 것을 요청과 응답으로 남겼다
- [x] 제출물 어디에도 실제 개인정보와 비밀값이 없다 (로그의 세션 값은 `***redacted***` 처리)
