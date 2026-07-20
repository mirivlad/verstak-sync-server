#!/usr/bin/env node
// Browser smoke driver for scripts/smoke-web.sh. It uses Node's bundled
// undici WebSocket client and Chromium DevTools; no npm package is required.
import { createRequire } from "node:module";
import { writeFile } from "node:fs/promises";

const require = createRequire(import.meta.url);
const { WebSocket } = require("undici");

const [baseURL, outputDir] = process.argv.slice(2);
if (!baseURL || !outputDir) throw new Error("usage: smoke-web-browser.mjs <base-url> <output-dir>");
const debugURL = process.env.CHROME_DEBUG_URL || "http://127.0.0.1:9223";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(check, label) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (await check()) return;
    await delay(100);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const targets = await (await fetch(`${debugURL}/json/list`)).json();
const target = targets.find((item) => item.type === "page");
if (!target?.webSocketDebuggerUrl) throw new Error("Chromium DevTools page target is unavailable");
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

let nextID = 1;
const pending = new Map();
socket.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  if (!message.id) return;
  const request = pending.get(message.id);
  if (!request) return;
  pending.delete(message.id);
  if (message.error) request.reject(new Error(`${message.error.message} (${message.error.code})`));
  else request.resolve(message.result);
});
function cdp(method, params = {}) {
  const id = nextID++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const result = await cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || "browser evaluation failed");
  return result.result.value;
}
async function navigate(path) {
  await cdp("Page.navigate", { url: new URL(path, baseURL).href });
  await waitFor(async () => String(await evaluate("location.href")).startsWith(new URL(path, baseURL).href), path);
	await waitFor(() => evaluate("document.readyState === 'complete'"), `${path} document readiness`);
}
async function submit(selector, values, expectedPath) {
  const payload = JSON.stringify(values);
  await evaluate(`(() => { const form = document.querySelector(${JSON.stringify(selector)}); if (!form) throw new Error('form not found: ${selector}'); const values = ${payload}; for (const [name, value] of Object.entries(values)) { const input = form.querySelector('[name="' + name + '"]'); if (!input) throw new Error('input not found: ' + name); input.value = value; } form.requestSubmit(); })()`);
  await waitFor(async () => new URL(await evaluate("location.href")).pathname === expectedPath, expectedPath);
}
async function screenshot(name) {
  const image = await cdp("Page.captureScreenshot", { format: "png" });
  await writeFile(`${outputDir}/${name}.png`, Buffer.from(image.data, "base64"));
}
async function confirmDialog(expectedPath) {
  await waitFor(() => evaluate("document.querySelector('#confirm-dialog')?.open === true"), "confirmation dialog");
  await evaluate("document.querySelector('#confirm-dialog button[value=confirm]').click()");
	await waitFor(() => evaluate("document.querySelector('#confirm-dialog')?.open === false"), "confirmation dialog close");
	await delay(300);
  await waitFor(async () => new URL(await evaluate("location.href")).pathname === expectedPath, expectedPath);
}
async function openRowDialog(rowText) {
  const before = await evaluate(`(() => { const row = [...document.querySelectorAll('tbody tr')].find((item) => item.textContent.includes(${JSON.stringify(rowText)})); if (!row) throw new Error('row not found: ${rowText}'); const box = row.getBoundingClientRect(); row.querySelector('[data-dialog-open]').click(); return { width: box.width, height: box.height }; })()`);
  await waitFor(() => evaluate("document.querySelector('.management-dialog[open]') !== null"), "management dialog");
  const after = await evaluate(`(() => { const row = [...document.querySelectorAll('tbody tr')].find((item) => item.textContent.includes(${JSON.stringify(rowText)})); const box = row.getBoundingClientRect(); return { width: box.width, height: box.height }; })()`);
  if (Math.abs(before.width - after.width) > 0.5 || Math.abs(before.height - after.height) > 0.5) throw new Error(`opening dialog resized table row: ${JSON.stringify({ before, after })}`);
}

await cdp("Page.enable");
await cdp("Runtime.enable");

// Public locale selector, then a real admin login through the rendered form.
await navigate("/");
await screenshot("public-en");
await waitFor(() => evaluate("Boolean(document.querySelector('.locale-form select'))"), "locale selector");
await evaluate("document.querySelector('.locale-form select').value = 'ru'; document.querySelector('.locale-form').requestSubmit()");
await waitFor(() => evaluate("document.documentElement?.lang === 'ru'"), "Russian locale");
await screenshot("public-ru");

await navigate("/admin/login");
await submit('form[action="/admin/login"]', { username: "admin", password: "browser-smoke-admin-password" }, "/admin/dashboard");

// Seed data before rendering admin views, so screenshots cover non-empty
// users/devices/vaults/storage/audit states.
await navigate("/admin/create-user");
await submit('form[action="/admin/create-user"]', { username: "browser-smoke-user", email: "browser-smoke@example.test", password: "browser-smoke-password" }, "/admin/users");
const paired = await fetch(`${baseURL}/api/client/pair`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ login: "browser-smoke-user", password: "browser-smoke-password", device_name: "Browser smoke laptop", vault_id: "browser-smoke-vault", client_version: "smoke" }) });
if (!paired.ok) throw new Error(`pairing smoke device failed: ${paired.status}`);

await navigate("/admin/dashboard");
await screenshot("admin-dashboard");

// Core admin navigation with populated data.
for (const [path, name] of [["/admin/users", "admin-users"], ["/admin/devices", "admin-devices"], ["/admin/vaults", "admin-vaults"], ["/admin/storage", "admin-storage"], ["/admin/audit", "admin-audit"], ["/admin/settings", "admin-settings"], ["/admin/diagnostics", "admin-diagnostics"]]) {
  await navigate(path);
  await screenshot(name);
}
await navigate("/admin/vaults");
const vaultDetail = await evaluate("document.querySelector('a[href^=\"/admin/vault/\"]')?.getAttribute('href')");
if (!vaultDetail) throw new Error("vault detail link not found");
await navigate(vaultDetail);
await screenshot("admin-vault-detail");
await navigate("/admin/users?q=browser-smoke-user");

// Exercise the destructive confirmation dialog by blocking and unblocking the
// temporary user. requestSubmit is intentionally not used for this action.
async function toggleTemporaryUser() {
  await openRowDialog("browser-smoke-user");
  await evaluate(`(() => { const dialog = document.querySelector('.management-dialog[open]'); const form = [...dialog.querySelectorAll('form')].find((item) => item.querySelector('[name=action]')?.value === 'toggle-user'); form.querySelector('[name=password]').value = 'browser-smoke-admin-password'; form.querySelector('button').click(); })()`);
  await confirmDialog("/admin/users");
  await navigate("/admin/users?q=browser-smoke-user");
}
await toggleTemporaryUser();
await toggleTemporaryUser();

// A password reset is generated server-side, rendered once with no secret in
// the URL, and invalidates any prior user session. Keep it only in this test
// process so the subsequent user login exercises the generated credential.
await openRowDialog("browser-smoke-user");
await evaluate(`(() => { const dialog = document.querySelector('.management-dialog[open]'); const form = [...dialog.querySelectorAll('form')].find((item) => item.querySelector('[name=action]')?.value === 'reset-user-password'); form.querySelector('[name=password]').value = 'browser-smoke-admin-password'; form.querySelector('button').click(); })()`);
await confirmDialog("/admin/password-result");
await waitFor(() => evaluate("!['Загрузка...', 'Loading...', '—'].includes(document.querySelector('.one-time-secret')?.textContent.trim())"), "generated one-time password");
await screenshot("admin-password-result");
const generatedPassword = await evaluate("document.querySelector('.one-time-secret')?.textContent.trim()");
if (!generatedPassword || (await evaluate("location.href")).includes(generatedPassword)) throw new Error("one-time password result is missing or leaked into the URL");
await navigate("/admin/users?q=browser-smoke-user");

// Revoke the real temporary device through the browser UI and assert the
// modal path again.
await navigate("/admin/devices?q=Browser%20smoke");
await openRowDialog("Browser smoke laptop");
await evaluate(`(() => { const dialog = document.querySelector('.management-dialog[open]'); const form = dialog.querySelector('form'); form.querySelector('[name=password]').value = 'browser-smoke-admin-password'; form.querySelector('button').click(); })()`);
await confirmDialog("/admin/devices");

// Server-side filters and HTML logout complete the browser path.
await navigate("/admin/audit?q=device");
await screenshot("admin-audit-filtered");
await evaluate("document.querySelector('form[action=\"/admin/logout\"]').requestSubmit()");
await waitFor(async () => new URL(await evaluate("location.href")).pathname === "/admin/login", "admin logout");

await navigate("/login");
await submit('form[action="/login"]', { username: "browser-smoke-user", password: generatedPassword }, "/dashboard");
await screenshot("user-dashboard");
await evaluate("document.querySelector('form[action=\"/logout\"]').requestSubmit()");
await waitFor(async () => new URL(await evaluate("location.href")).pathname === "/login", "user logout");

socket.close();
console.log("interactive Chromium web smoke passed");
