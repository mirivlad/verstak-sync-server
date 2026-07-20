# Beta Web GUI Design

Date: 2026-07-20

## Goal

Make the synchronization server console trustworthy and usable for beta users. Large administrative actions must not distort tables, and the public header must reflect the authenticated user or administrator session.

## Scope

This change covers the server-rendered web GUI only:

- user and device management tables in the administrator console;
- the shared public/user/admin header;
- focused template, handler, CSS, JavaScript, and browser-smoke coverage.

It does not change synchronization protocol endpoints, authentication rules, database schema, or release publishing.

## Administrative Actions

### Current problem

User actions are rendered as several forms inside a `<details>` element in the final table cell. Expanding it increases the row height and table intrinsic width. Device actions have the same structural risk because privileged forms remain inside table cells.

### Design

Each row keeps only a compact `Manage` button. The button opens a server-rendered native `<dialog>` associated with that row.

The user dialog contains clearly separated sections for:

- profile fields;
- account blocking state;
- password reset or generated password;
- permanent deletion.

The device dialog contains device identity and revoke/delete actions. Privileged actions continue to require the administrator password. Destructive submitters continue through an explicit confirmation step. Existing POST endpoints, action names, CSRF validation, authorization checks, and redirect behavior remain unchanged.

Dialogs use a bounded desktop width, `max-height` based on the viewport, internal scrolling, and consistent padding. Escape, the close button, and a cancel action close the dialog without submitting. Opening and closing a dialog must not alter table row dimensions or horizontal scroll width.

With the existing page size, one server-rendered dialog per row is acceptable and avoids AJAX state, client-side data templating, and new API exposure.

## Authentication-aware Header

### Current problem

The shared layout always renders login and registration links. `webPage` has no authenticated-session state. Language selection follows the auth links and independently pushes itself to the right. Logout is duplicated inside the user dashboard and administrator navigation.

### Design

The renderer determines a presentation-only authentication context:

- `guest`;
- `user`;
- `admin`.

Only validated, unexpired sessions count. On `/admin` routes an administrator session takes precedence; outside `/admin`, a user session takes precedence. Invalid cookies produce the guest header and never grant access.

The header contains the brand on the left and one action group on the right. The group order is fixed:

1. locale selector;
2. contextual dashboard link when authenticated;
3. login and optional registration links for a guest, or the correct POST logout form for an authenticated session.

The logout form uses the existing scope-specific endpoint and CSRF value. Duplicate logout controls are removed from the user dashboard heading and administrator side navigation. An authenticated GET request to its matching login page redirects to its dashboard, preventing a contradictory login form from being shown.

On small screens the right action group may wrap as one unit, while locale selection remains before authentication actions.

## Error and Security Behaviour

- Modal forms preserve server-side validation and localized flash messages.
- A missing or expired session never exposes authenticated navigation.
- Logout remains POST-only and CSRF-protected.
- Administrator password values and generated passwords never enter query strings or reusable page state.
- Authenticated pages retain `Cache-Control: no-store`.

## Verification

Automated tests will cover:

- guest, user, and administrator header variants;
- language-before-auth ordering;
- registration-disabled guest navigation;
- correct user/admin logout action and CSRF field;
- redirect away from login for a matching valid session;
- invalid/expired cookie fallback;
- absence of `<details>` and privileged forms inside table cells;
- dialog open/close, destructive confirmation, and successful existing actions;
- stable row height and bounded dialog layout in Chromium smoke tests.

The complete server test suite, race-appropriate focused checks, web smoke tests, release build scripts, and artifact checksum verification run before completion.

## Success Criteria

- Opening management actions never expands or widens a table row.
- All existing administrative operations still succeed with the same authorization and CSRF requirements.
- A signed-in user or administrator is never offered login or registration in the header.
- Locale selection appears before authentication actions.
- Logout is visible once, targets the correct scope, and invalidates the server-side session.
