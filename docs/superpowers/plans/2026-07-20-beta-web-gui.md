# Beta Web GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace table-embedded administrator forms with accessible dialogs and make the shared server header accurately reflect guest, user, and administrator sessions.

**Architecture:** Keep all pages server-rendered and preserve existing POST handlers. Add presentation-only auth context during rendering, group header actions in the shared layout, and open one native dialog per displayed table row with the existing confirmation flow.

**Tech Stack:** Go `net/http`, `html/template`, SQLite-backed sessions, embedded CSS/JavaScript, Go tests, Chromium CDP smoke script.

## Global Constraints

- Do not change synchronization protocol endpoints, authentication rules, or the database schema.
- Logout remains POST-only and CSRF-protected.
- Administrator passwords and generated passwords never enter URLs or reusable page state.
- Dialogs must have safe padding, bounded viewport height, and internal scrolling.
- Build release artifacts locally but do not publish them.

---

### Task 1: Authentication-aware shared header

**Files:**
- Modify: `internal/server/web_render.go`
- Modify: `internal/server/web/templates/layout.html`
- Modify: `internal/server/web/templates/dashboard.html`
- Modify: `internal/server/web/templates/admin_nav.html`
- Modify: `internal/server/web/static/app.css`
- Modify: `internal/server/handlers_web_user.go`
- Modify: `internal/server/handlers_admin.go`
- Test: `internal/server/web_locale_test.go`

**Interfaces:**
- Produces: `webPage.AuthScope string` with exact values `guest`, `user`, or `admin`.
- Produces: `webPage.AuthDashboardURL string` and `webPage.AuthLogoutURL string`.
- Consumes: existing `loadSession(token, scope)`, scope-specific cookies, `.CSRF`, and locale fields.

- [ ] **Step 1: Add failing renderer tests**

Add table-driven requests that render a public page with no session, a valid user session, and a valid admin session on `/admin/dashboard`. Assert guest HTML contains `/login` and locale before auth navigation; authenticated HTML contains the correct dashboard and POST logout action and contains neither guest login nor registration.

```go
cases := []struct {
    name, path, scope, wantLogout string
    wantGuest                    bool
}{
    {name: "guest", path: "/", wantGuest: true},
    {name: "user", path: "/dashboard", scope: sessionScopeUser, wantLogout: `/logout`},
    {name: "admin", path: "/admin/dashboard", scope: sessionScopeAdmin, wantLogout: `/admin/logout`},
}
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `go test ./internal/server -run 'Test.*Header|Test.*LoginRedirect' -count=1`

Expected: FAIL because the header still always contains login/registration and has no contextual logout.

- [ ] **Step 3: Add presentation-only auth context**

Add exact page fields and a helper that validates the cookie appropriate to the request path without redirecting. Prefer admin on `/admin`; prefer user elsewhere. Set dashboard/logout URLs and `Cache-Control: no-store` for authenticated context.

```go
type webPage struct {
    // existing fields
    AuthScope        string
    AuthDashboardURL string
    AuthLogoutURL    string
}
```

- [ ] **Step 4: Make layout navigation contextual**

Wrap locale and auth controls in `.header-actions`, render locale first, render guest links only for `guest`, and render dashboard plus a CSRF POST logout form for authenticated scopes. Remove the duplicate dashboard/admin-nav logout forms.

- [ ] **Step 5: Redirect authenticated GET login requests**

For `/login` and `/admin/login`, validate only the matching session and redirect to `/dashboard` or `/admin/dashboard`. Do not let a user session authorize an administrator page or the reverse.

- [ ] **Step 6: Run focused and complete Go tests**

Run: `go test ./internal/server -run 'Test.*Header|Test.*LoginRedirect|TestWebSessionScopes' -count=1`

Expected: PASS.

Run: `go test ./...`

Expected: PASS.

- [ ] **Step 7: Commit and push**

```bash
git add internal/server/web_render.go internal/server/web/templates/layout.html internal/server/web/templates/dashboard.html internal/server/web/templates/admin_nav.html internal/server/web/static/app.css internal/server/handlers_web_user.go internal/server/handlers_admin.go internal/server/web_locale_test.go
git commit -m "fix(web): reflect authenticated session in header"
git push origin fix/beta-readiness-2026-07-20
```

### Task 2: User management dialogs

**Files:**
- Modify: `internal/server/web/templates/admin_users.html`
- Modify: `internal/server/web/static/app.css`
- Modify: `internal/server/web/static/app.js`
- Test: `internal/server/web_locale_test.go`
- Test: `scripts/smoke-web-browser.mjs`

**Interfaces:**
- Consumes: existing `/admin/action` POST contract, `action` values, CSRF token, administrator password, and global destructive confirmation dialog.
- Produces: buttons with `data-dialog-open` and dialogs with matching stable IDs.

- [ ] **Step 1: Add a failing template contract test**

Render the users page with one user and assert the row contains one manage button, no `<details>`, and no password input. Assert the associated dialog contains profile fields and submitters for update, block/unblock, reset password, and delete.

- [ ] **Step 2: Run the test and confirm failure**

Run: `go test ./internal/server -run 'Test.*AdminUsers.*Dialog' -count=1`

Expected: FAIL because forms are currently embedded in `<details>` inside the row.

- [ ] **Step 3: Render one dialog per user outside the table flow**

Keep only the manage button in the action cell. Place dialogs after the table card, retaining existing action names and localized labels. Separate ordinary profile editing from destructive actions and retain administrator reauthentication.

- [ ] **Step 4: Add generic dialog open/close behavior**

Use event delegation for `[data-dialog-open]` and `[data-dialog-close]`. Call `showModal()`, return focus to the opener on close, and allow Escape/cancel without submission. Keep the existing confirmation submitter logic intact.

- [ ] **Step 5: Add bounded dialog styles**

Use `width:min(calc(100% - 2rem), 760px)`, `max-height:calc(100vh - 2rem)`, `overflow:auto`, and consistent `1.25rem` or larger padding. Ensure forms and danger sections do not impose table width.

- [ ] **Step 6: Update Chromium smoke actions**

Replace the `<details>` selectors with manage-button/dialog selectors. Before opening, record the row bounding box; after opening, assert its height and width are unchanged. Exercise block/unblock and password reset through the dialog.

- [ ] **Step 7: Run focused tests and browser smoke**

Run: `go test ./internal/server -run 'Test.*AdminUsers.*Dialog' -count=1`

Expected: PASS.

Run: `./scripts/smoke-web.sh`

Expected: `interactive web browser smoke passed`.

- [ ] **Step 8: Commit and push**

```bash
git add internal/server/web/templates/admin_users.html internal/server/web/static/app.css internal/server/web/static/app.js internal/server/web_locale_test.go scripts/smoke-web-browser.mjs
git commit -m "fix(admin): move user actions into dialogs"
git push origin fix/beta-readiness-2026-07-20
```

### Task 3: Device management dialogs

**Files:**
- Modify: `internal/server/web/templates/admin_devices.html`
- Modify: `scripts/smoke-web-browser.mjs`
- Test: `internal/server/web_locale_test.go`

**Interfaces:**
- Consumes: generic dialog JavaScript/CSS from Task 2 and existing device action contract.
- Produces: compact device row action and scope-correct revoke/delete dialog.

- [ ] **Step 1: Add a failing device-dialog template test**

Assert the device table cell contains no password input/form and the dialog contains device identity, administrator password, CSRF, and the existing action submitter.

- [ ] **Step 2: Run the test and confirm failure**

Run: `go test ./internal/server -run 'Test.*AdminDevices.*Dialog' -count=1`

Expected: FAIL because the device form is still inline.

- [ ] **Step 3: Move device actions into the shared dialog pattern**

Keep endpoint/action values unchanged and reuse the generic opener, close behavior, and danger confirmation.

- [ ] **Step 4: Update and run browser smoke**

Open the device dialog, submit the existing action, and assert the row did not resize.

Run: `./scripts/smoke-web.sh`

Expected: PASS with user, device, user-dashboard, locale, and header screenshots.

- [ ] **Step 5: Run complete tests, commit, and push**

Run: `go test ./...`

Expected: PASS.

```bash
git add internal/server/web/templates/admin_devices.html internal/server/web_locale_test.go scripts/smoke-web-browser.mjs
git commit -m "fix(admin): move device actions into dialogs"
git push origin fix/beta-readiness-2026-07-20
```

### Task 4: Server release verification

**Files:**
- Generated only: `release/`

**Interfaces:**
- Consumes: passing repository state.
- Produces: local Linux amd64 sync-server archive and SHA256 manifest; publishes nothing.

- [ ] **Step 1: Run final verification**

Run: `git diff --check && go test ./... && ./scripts/smoke-web.sh`

Expected: every command passes.

- [ ] **Step 2: Build the local release package**

Run: `./scripts/release.sh 0.1.0-beta.20260720`

Expected: a non-empty `release/verstak-sync-server-linux-amd64-0.1.0-beta.20260720.tar.gz` and `release/SHA256SUMS`.

- [ ] **Step 3: Verify checksums and archive listing**

Run: `cd release && sha256sum -c SHA256SUMS && tar -tzf verstak-sync-server-linux-amd64-0.1.0-beta.20260720.tar.gz >/dev/null`

Expected: checksum `OK` and successful archive listing. Do not run the publish script.
