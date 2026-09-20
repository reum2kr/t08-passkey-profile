// Quick local smoke test: does one full register -> login cycle succeed
// using a Chrome DevTools Protocol virtual authenticator? Not the full
// evidence script — just a fast correctness check before writing the
// real evidence collector.
import { chromium } from 'playwright';

const BASE = process.env.BASE_URL || 'http://localhost:3000';

const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});

page.on('console', (msg) => console.log('[page]', msg.text()));

await page.goto(BASE + '/#private');

// register
await page.click('#tabRegister');
await page.fill('#registerUsername', 'smoketest1');
await page.fill('#registerDeviceName', '가상 인증기 1');
await page.click('#btnRegister');
await page.waitForSelector('#private-unlocked:not([hidden])', { timeout: 10000 });
console.log('REGISTER OK, unlocked visible');

const who = await page.textContent('#whoAmI');
console.log('logged in as', who);

await page.click('#btnLogout');
await page.waitForSelector('#private-locked:not([hidden])', { timeout: 10000 });
console.log('LOGOUT OK');

await page.click('#tabLogin');
await page.fill('#loginUsername', 'smoketest1');
await page.click('#btnLogin');
await page.waitForSelector('#private-unlocked:not([hidden])', { timeout: 10000 });
console.log('LOGIN OK');

await browser.close();
console.log('SMOKE TEST PASSED');
