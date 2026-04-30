# Enterprise Auth - Identity and Access Management for WordPress

Enterprise Auth is a WordPress plugin for enterprise-ready authentication, provisioning, and Multisite-aware identity workflows.

It combines:

- Passkeys (WebAuthn)
- Tenant-scoped device-bound passkey enforcement with controlled migration for legacy synced credentials
- SAML 2.0 Service Provider support
- OpenID Connect (OIDC) support
- Domain-based SSO routing
- Just-In-Time user provisioning
- Network-managed Multisite defaults with per-setting site override policy
- Site-scoped private content login gating for private posts and pages
- User IAM visibility on WordPress Users and Profile screens
- Read-only WP-CLI operator commands for providers, sites, users, routing, passkeys, settings, and SCIM posture
- Multisite-aware tenant isolation for identity metadata, re-auth cookies, and protocol transient state
- Group-to-role mapping with wildcard fallback
- Break-glass admin isolation
- Immutable IdP UID account binding
- Configurable JIT role ceiling
- SCIM 2.0 user provisioning and deprovisioning
- SCIM delete with site-level content steward reassignment and optional network-wide deprovision
- SCIM group-to-role entitlement mapping
- Custom attribute mapping per IdP with enterprise preset templates
- SSO-only account lockdown (password login and password reset blocked for SSO-managed users)
- Email change protection for SSO-managed users
- Session expiry auto re-authentication (seamless redirect back to the correct IdP)
- Force Sign-In Mode — per-IdP ForceAuthn (SAML) and prompt=login (OIDC)
- First-link clean sweep for existing local accounts that become IdP-managed
- Identity event audit hooks for SSO login and SCIM lifecycle actions
- Passkey credential audit state with compliance status, registration origin, and last-used tracking
- REST API cache-control hardening — all plugin endpoints return `Cache-Control: no-store` to prevent CDN/proxy caching of dynamic responses

## Highlights

- Identity-first login UX on `wp-login.php` with correct local vs SSO routing
- Passwordless login with passkeys
- Attestation-gated passkey enrollment with optional strict device-bound mode and automatic step-up migration for legacy synced credentials
- Network control plane for Multisite defaults, inherited settings, and site override enforcement
- Private content login gate that preserves `redirect_to` without forcing whole-site authentication
- Read-only IAM visibility in wp-admin user management screens
- Read-only operator surface under `wp enterprise-auth ...`
- SAML metadata endpoint and ACS flow
- OIDC authorization and callback flow
- Unified provisioning engine for SAML and OIDC
- SCIM 2.0 endpoint with Bearer token auth, rate limiting, and production delete semantics
- Multisite-safe `SiteMetaKeys` isolation for SSO / SCIM bindings, cookies, and transient state
- React admin UI for provider management
- Break-glass admin isolation — SSO cannot target administrator accounts
- Strict account binding via immutable IdP UID (OIDC `sub` / SAML NameID)
- Configurable JIT role ceiling to prevent privilege escalation
- Capability-aware role hardening blocks privileged roles for standard tenant IdPs
- Custom attribute mapping per IdP with one-click presets for Azure AD, Okta, Shibboleth, and more
- SSO-only account lockdown — password login and password reset disabled for SSO-managed users
- Email change protection — SSO-managed users cannot change their email address
- Session expiry auto re-auth — expired sessions redirect transparently back to the user's IdP
- Force Sign-In Mode — optional per-IdP setting to bypass cached IdP sessions (SAML ForceAuthn / OIDC prompt=login)
- SCIM delete supports explicit content steward reassignment, fail-closed 409 responses, and optional network-scope deprovision on Multisite
- Audit-friendly `ea_identity_event` hooks on SSO login and SCIM lifecycle actions
- REST API cache-control hardening — `Cache-Control: no-store, no-cache, must-revalidate, private` on all `enterprise-auth/` REST responses to prevent web cache deception and poisoning attacks

## Requirements

- WordPress 6.0+
- PHP 8.3+
- Composer dependencies installed (`vendor/`)
- Frontend assets built (`build/`)

## Installation

### Production-style install

1. Place the plugin in `wp-content/plugins/enterprise-iam`.
2. Ensure `vendor/` and `build/` are present.
3. Activate the plugin from WordPress admin.
4. Configure providers in `WP Admin -> Enterprise Auth`.
5. On Multisite, configure the SCIM Deprovision Steward on each site before enabling automated deprovisioning.

### Development install

```bash
composer install
npm install
npm run build
```

For watch mode during UI development:

```bash
npm run start
```

## End-to-End Testing

The repository includes a Playwright harness for the SEC audit lab described in `testsite.md`.

### Setup

```bash
cp .env.e2e.example .env.e2e
npm run e2e:install
```

On Linux hosts, install the Playwright system packages once before running the browser-based specs:

```bash
npm run e2e:install-deps
```

Defaults in the harness target the local multisite lab at `https://secaudit.localhost` with the documented local test accounts. Override them in `.env.e2e` if your lab differs.

### Run

```bash
npm run e2e:list
npm run e2e
```

The starter specs cover:

- admin smoke coverage for the Enterprise Auth screen
- passkey registration and passkey login using a Chromium virtual authenticator
- fixture-driven OIDC and SAML provider seeding
- mocked OIDC and SAML browser flows covering redirect construction, metadata, and masked callback / ACS failures
- SCIM token generation plus create, suspend, and delete smoke coverage

Fixture payloads live under `tests/e2e/fixtures/` so you can extend them for your own IdP and provisioning scenarios.

## Static Analysis

PHPCS with WordPress Coding Standards (WPCS) is configured via `phpcs.xml.dist`.

```bash
composer lint        # Run PHPCS static analysis
composer lint:fix    # Run PHPCBF to auto-fix style issues
```

If your local PHP installation lacks `dom`, `simplexml`, or related XML extensions (common on macOS/Linux without a full PHP build), run the tools inside the Docker container instead:

```bash
docker exec wordpress sh -lc \
  'cd /var/www/html/wp-content/plugins/enterprise-iam && php vendor/bin/phpcs'
```

> **Note:** If you recreate the Docker container, re-register WPCS once with:
> ```bash
> docker exec wordpress sh -lc \
>   'cd /var/www/html/wp-content/plugins/enterprise-iam && php vendor/bin/phpcs \
>   --config-set installed_paths \
>   vendor/wp-coding-standards/wpcs,vendor/phpcsstandards/phpcsextra,vendor/phpcsstandards/phpcsutils'
> ```

## Configuration Overview

### Passkeys

Enterprise Auth uses attestation-gated platform passkey enrollment for passwordless login.

- Administrators can register managed passkeys from the Enterprise Auth admin UI.
- The **Require Device-Bound Authenticators** tenant setting rejects backup-eligible synced passkeys during new enrollment.
- When strict mode is enabled, existing backup-eligible credentials are marked as legacy non-compliant. A user who signs in with one of those credentials is redirected into a self-service **Security Upgrade Required** flow until they register a compliant replacement.
- Credential records retain compliance status, registration origin, and last-used timestamps so the migration flow can distinguish compliant versus legacy credentials safely.

Current attestation scope in the local trust bundle is limited to:

- Windows Hello Hardware Authenticator
- Windows Hello VBS Hardware Authenticator
- Approved Android platform authenticator metadata bundled with the plugin

Apple enterprise passkey attestation is not bundled yet.

### Access Gating

Enterprise Auth includes an optional private-content login gate.

- When enabled, logged-out visitors requesting private posts or pages are redirected to `wp-login.php` with the destination preserved in `redirect_to`.
- Public content remains publicly reachable.
- The plugin does not currently force authentication for the entire frontend.

### SAML

- Configure IdP metadata fields in the admin UI.
- Use the SAML metadata endpoint to register this site as a Service Provider with your IdP.
- Route users by domain to the correct SAML IdP.

### OIDC

Configure:

- Issuer
- Authorization endpoint
- Token endpoint
- UserInfo endpoint
- JWKS URI
- Client ID and client secret

Users are redirected through the OIDC Authorization Code flow and validated on callback.

The plugin stores OIDC `state`, `nonce`, and `code_verifier` in short-lived, blog-scoped transients during the redirect flow. Callback verification does not depend on plugin-managed PHP sessions.

## Multisite and Tenant Isolation

On single-site installs, the plugin keeps its legacy key layout and routing behavior. On WordPress Multisite, Enterprise Auth adds explicit tenant isolation for identity state that would otherwise bleed across the shared network user table and browser cookie space.

- SSO and SCIM identity bindings use site-scoped usermeta keys through `SiteMetaKeys`.
- Seamless SSO re-auth uses a per-site last-IdP cookie to avoid cross-subdomain and cross-site bleed.
- SAML request IDs, OIDC verification state, and WebAuthn challenge transients are blog-scoped.
- Passkey step-up requirement flags are stored in site-scoped usermeta, so a strict passkey policy on one tenant does not spill into other sites on the same network.
- SCIM provisioning can attach an existing network user to the current site instead of creating a duplicate global account.
- SCIM network deprovision evaluates each site independently and applies per-site reassignment policy before removing memberships.

## Multisite Governance

When network-activated, Enterprise Auth adds a network control plane for effective settings and operator visibility.

- Super admins can define network defaults and choose which settings site admins may override locally.
- Site admins see effective values plus scope metadata for inherited, overridden, and network-locked settings.
- The current policy set covers lockdown mode, application passwords, device-bound passkeys, private content login gating, role ceiling, session timeout, and SCIM deprovision steward selection.
- Runtime behavior uses the same resolved values exposed in the UI and CLI.

## WP-CLI Operator Surface

Enterprise Auth exposes a read-only operational namespace for safe inspection and automation:

```bash
wp enterprise-auth provider list
wp enterprise-auth site list
wp enterprise-auth settings get --blog-id=2
wp enterprise-auth user inspect admin@example.com --blog-id=2
wp enterprise-auth route resolve user@example.com --blog-id=2
wp enterprise-auth passkey audit --blog-id=2
wp enterprise-auth scim status --blog-id=2
```

Use explicit scope in Multisite. Site-local commands use `--blog-id=<id>`, and network-wide inspection uses `--network` where supported.

## WordPress Admin Visibility

The plugin adds a read-only IAM status layer to wp-admin for support and audit workflows.

- Users list columns surface identity source, provider binding, passkey summary, and suspension posture.
- Profile and Edit User screens show the current site's identity context in Multisite.
- The visibility layer is intentionally read-only and does not expose secrets.

## Custom Attribute Mapping

By default, the plugin uses a multi-format fallback chain for reading email, first name, and last name from IdP assertions (covering Azure AD URIs, Shibboleth OIDs, and standard short names simultaneously). When your IdP uses non-standard claim keys, you can override the defaults per provider.

### Enabling override

In the SAML or OIDC editing form, toggle **Override Default Attribute Mapping**. Three text inputs appear:

| Field | Description |
|---|---|
| Email Attribute Key | The assertion key or claim name containing the user's email address |
| First Name Attribute Key | The claim name for the user's given name |
| Last Name Attribute Key | The claim name for the user's family name |

The form also includes a **Provider Type** selector. When a known provider family is selected, the override UI recommends the matching preset and auto-fills it the first time override mode is enabled with empty custom fields.

### IdP Presets

A **Load Preset** dropdown auto-fills all three keys for common enterprise IdPs. Selecting a preset fills the inputs; you can then adjust any individual field before saving.

**SAML Presets**

| Preset | Email | First Name | Last Name |
|---|---|---|---|
| Standard / Okta | `email` | `firstName` | `lastName` |
| Azure AD (Microsoft Entra) | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` |
| Shibboleth / InCommon (OIDs) | `urn:oid:0.9.2342.19200300.100.1.3` | `urn:oid:2.5.4.42` | `urn:oid:2.5.4.4` |

**OIDC Presets**

| Preset | Email | First Name | Last Name |
|---|---|---|---|
| Standard OIDC (Okta / Google / Auth0) | `email` | `given_name` | `family_name` |
| Azure AD OIDC | `preferred_username` | `given_name` | `family_name` |

### Persistence

The toggle state (`override_attribute_mapping`) and three keys (`custom_email_attr`, `custom_first_name_attr`, `custom_last_name_attr`) are stored alongside all other IdP configuration in `wp_options` (`enterprise_auth_idps`) and are fully sanitized server-side before persistence.

### Provisioning behavior

When override is enabled, the custom keys replace the built-in fallback chain. If neither the custom key nor any fallback yields a valid email, provisioning is aborted with an error. When override is disabled (the default), the full multi-format fallback chain is used unchanged.

## Role Mapping

Role mapping is shared across SAML and OIDC provisioning.

- Exact group mapping is case-insensitive.
- Wildcard mapping with `*` is supported as a fallback default role.
- The `administrator` role is excluded from the role mapping UI as a defence-in-depth measure.

Example:

```text
Engineering -> editor
Marketing   -> author
*           -> subscriber
```

### Role Ceiling

A **Role Ceiling** setting (General tab) caps the maximum role that SSO/JIT provisioning can assign, regardless of what the IdP sends. Default is `editor`. Accepted values: `editor`, `author`, `contributor`, `subscriber`.

This prevents a compromised or misconfigured IdP from granting `administrator` access to WordPress.

### Privileged Role Guardrails

Role assignment is capability-aware, not just name-aware. Roles that expose capabilities such as `manage_options`, `switch_themes`, or `manage_network` are blocked for standard tenant IdPs even if the textual role name would otherwise pass the ceiling check. This prevents custom elevated roles from bypassing a simple name-based allowlist.

## Provisioning Behaviour

On successful SSO authentication, the plugin applies the following steps in order:

1. **Break-glass check** — rejects SSO login for user ID 1 and any `administrator` account. These accounts must always log in locally (password or passkey).
2. **Primary user lookup** — searches for an existing user by the IdP's immutable unique identifier stored in `_enterprise_auth_idp_uid` usermeta. This is the OIDC `sub` claim or the SAML `NameID`.
3. **First-time binding** — if no UID match is found, falls back to email lookup. On a successful email match the IdP UID is stored for all future logins. If the stored UID does not match the incoming UID, the login is blocked (IdP spoofing prevention).
4. **First-link clean sweep** — when an existing local account becomes IdP-managed for the first time, the plugin revokes the local password, application passwords, and active sessions before finalizing the binding.
5. **Multisite attach** — if a matching network user already exists but is not yet a member of the current site, the plugin attaches the user to the current site instead of creating a duplicate global account.
6. **JIT creation** — if no matching user exists, creates a new WordPress account at `subscriber` level and stores both the IdP provider ID and UID.
7. **Role mapping** — applies group-to-role mapping, blocked-capability checks, and the configured Role Ceiling.
8. **Login** — sets the auth cookie, records the last-used IdP for the current site, emits `ea_identity_event`, and fires `wp_login`.

### Login Routing

The domain router (`/route-login`) returns `local` for any WordPress account that has no SSO provider binding, even if the email domain is mapped to an IdP. This ensures break-glass admin accounts and other intentionally-local accounts on SSO domains always reach the password/passkey form.

## SCIM 2.0 Provisioning

The plugin exposes a SCIM 2.0 (RFC 7643/7644) endpoint for automated user lifecycle management from enterprise identity providers.

### Authentication

All SCIM endpoints require a `Authorization: Bearer <token>` header. The token's bcrypt hash is stored in `wp_options` under `enterprise_iam_scim_token`.

### SCIM Admin UI

The admin app now includes a **SCIM Provisioning** tab where administrators can:

- View the absolute SCIM base URL to provide to the IdP
- Generate a new SCIM token from the UI
- Configure a site-level **Deprovision Steward** for safe content reassignment during SCIM delete operations
- Copy the plaintext token exactly once (never retrievable later)

Token generation uses `POST /wp-json/enterprise-auth/v1/settings/scim-token` and stores only a bcrypt hash server-side.

### Rate Limiting

SCIM endpoints enforce a 300 requests/minute rate limit using WordPress transients. Exceeding the limit returns HTTP 429.

### User Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/scim/v2/Users` | List users as a SCIM ListResponse. Supports `startIndex`, `count`, and basic `filter` (`userName eq "..."`) for connector validation/reconciliation. |
| `POST` | `/scim/v2/Users` | Create a new user. Maps `userName` → email, `externalId` → immutable SCIM binding, `name` → first/last name. On Multisite, an existing network user can be attached to the current site instead of duplicated. Returns 201 or 409 on conflict. |
| `GET` | `/scim/v2/Users/{id}` | Fetch a single user by SCIM/WP user ID. Returns 404 when missing. |
| `PUT` | `/scim/v2/Users/{id}` | Full replace of a user's attributes. |
| `PATCH` | `/scim/v2/Users/{id}` | Partial update. Supports `active: false` to suspend (remove roles, set site-scoped SCIM suspension meta, destroy sessions) and `active: true` to reactivate. Handles both standard and Azure AD PatchOp formats. |
| `DELETE` | `/scim/v2/Users/{id}` | Deprovision a user. On Multisite this removes the current-site membership and clears current-site identity bindings; on single-site it hard-deletes the user once reassignment is safe. Supports `?scope=network` on Multisite for network-wide deprovision. |

Administrator accounts (user ID 1 and `administrator` role) are protected from SCIM modifications (HTTP 403).

### Deprovisioning Policy

The SCIM delete implementation is explicit and fail-closed.

- On the current site, authored content is reassigned to the configured Deprovision Steward when available.
- If no steward is configured, the plugin falls back deterministically to the lowest-ID eligible local administrator on that site.
- If authored content exists and no valid reassignment target can be resolved, delete is rejected with HTTP 409 instead of proceeding partially.
- On Multisite, `DELETE /Users/{id}?scope=network` preflights every site membership first. If any site has authored content and no valid reassignment target, or if any membership is protected, the entire network operation is rejected before memberships are removed.
- Explicit network-scope deprovision sets a network-wide suspension flag so the user cannot continue authenticating after all site memberships are removed.

### Audit Events

Enterprise Auth emits `ea_identity_event` actions on successful SSO login and SCIM lifecycle operations.

- `sso_login` is emitted after a successful SSO-authenticated WordPress login.
- `scim_create`, `scim_update`, `scim_delete`, `scim_delete_rejected`, and `scim_delete_failed` are emitted for SCIM lifecycle activity.
- SCIM delete events include request scope, reassignment plan, external identifier, and request metadata when available, making it straightforward to forward the event stream into SIEM or audit logging pipelines.

### Group Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/scim/v2/Groups` | List groups as a SCIM ListResponse (WordPress roles are exposed as SCIM Groups). |
| `POST` | `/scim/v2/Groups` | Create a group. The `displayName` is matched against the existing role mapping engine and applied to all `members`. |
| `PATCH` | `/scim/v2/Groups/{id}` | Update group membership. Supports `add`/`replace` operations on the `members` path. |

Group role assignment uses the same mapping engine as SAML/OIDC (exact match → `*` wildcard fallback), respecting the configured Role Ceiling.

### Suspension & Login Block

When an IdP sends `PATCH` with `active: false`, the user's roles are removed and a site-scoped SCIM suspension flag is set. Suspended users are blocked from all login methods (password, passkey, SSO) with the message "Account suspended by Identity Provider." Explicit Multisite network deprovision also sets a network-wide suspension flag so the account remains blocked even after all site memberships are removed.

## Targeted Security Verification (Manual curl)

Use this focused plan to validate two hardening controls end-to-end:

- OIDC federation flow hard-fails on HTTP transport
- SCIM pre-auth failed-attempt throttling triggers before sustained brute-force traffic

### Setup

```bash
export BASE_HTTPS="https://secaudit.localhost"
export BASE_HTTP="http://secaudit.localhost"
export OIDC_IDP_ID="your-oidc-idp-id"
export SCIM_TOKEN="your-valid-scim-token"
```

### 1) OIDC HTTPS control check (expected success path)

```bash
curl -isk -D - -o /dev/null \
  "$BASE_HTTPS/wp-json/enterprise-auth/v1/oidc/login?idp_id=$OIDC_IDP_ID"
```

Expected:

- `302` status
- `Location` header points to the configured OIDC authorization endpoint

### 2) OIDC HTTP hard-fail check (new transport guard)

```bash
curl -isk -D - -o /dev/null \
  "$BASE_HTTP/wp-json/enterprise-auth/v1/oidc/login?idp_id=$OIDC_IDP_ID"
```

Expected:

- Plugin-level hard-fail: `500` status with OIDC initiation error payload
- If your edge/web server force-redirects HTTP to HTTPS first, you may see `301`/`308` instead. In that case, run this check against a non-redirecting app path in a staging/sandbox environment to verify the plugin guard itself.

### 3) SCIM pre-auth throttle check (invalid token flood)

```bash
for i in $(seq 1 35); do
  code=$(curl -ks -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer invalid-$i" \
    "$BASE_HTTPS/wp-json/enterprise-auth/v1/scim/v2/Users")
  printf "%02d -> %s\n" "$i" "$code"
done
```

Expected:

- Initial invalid attempts return `401`
- After the pre-auth failure budget is exhausted, responses switch to `429`

### 4) SCIM failure-budget reset on successful auth

```bash
curl -ks -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  "$BASE_HTTPS/wp-json/enterprise-auth/v1/scim/v2/Users"

curl -ks -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer invalid-after-success" \
  "$BASE_HTTPS/wp-json/enterprise-auth/v1/scim/v2/Users"
```

Expected:

- Valid token request returns `200`
- Next invalid attempt returns `401` (not `429`), confirming failure counter reset

### Expected Status Matrix

| Scenario | Endpoint | Expected Status | Notes |
|---|---|---|---|
| OIDC over HTTPS | `GET /oidc/login?idp_id=...` | `302` | Redirects to IdP authorization endpoint |
| OIDC over HTTP | `GET /oidc/login?idp_id=...` | `500` (plugin guard) or `301/308` (edge redirect) | `500` confirms plugin transport hard-fail is active |
| SCIM invalid token before threshold | `GET /scim/v2/Users` | `401` | Unauthorized, failure count increments |
| SCIM invalid token after threshold | `GET /scim/v2/Users` | `429` | Pre-auth abuse throttle engaged |
| SCIM valid token | `GET /scim/v2/Users` | `200` | Success path clears failure counter |
| Invalid token immediately after valid | `GET /scim/v2/Users` | `401` | Confirms counter reset on success |

## Main Endpoints

- `POST /wp-json/enterprise-auth/v1/route-login`
- `GET /wp-json/enterprise-auth/v1/saml/metadata`
- `GET /wp-json/enterprise-auth/v1/saml/login?idp_id={id}`
- `POST /wp-json/enterprise-auth/v1/saml/acs`
- `GET /wp-json/enterprise-auth/v1/oidc/login?idp_id={id}`
- `GET /wp-json/enterprise-auth/v1/oidc/callback`
- `GET|POST /wp-json/enterprise-auth/v1/passkeys/register`
- `GET|POST /wp-json/enterprise-auth/v1/passkeys/login`
- `POST /wp-json/enterprise-auth/v1/settings/scim-token`
- `GET|POST /wp-json/enterprise-auth/v1/scim/v2/Users`
- `GET|PUT|PATCH|DELETE /wp-json/enterprise-auth/v1/scim/v2/Users/{id}`
- `DELETE /wp-json/enterprise-auth/v1/scim/v2/Users/{id}?scope=network` (Multisite only)
- `GET|POST /wp-json/enterprise-auth/v1/scim/v2/Groups`
- `PATCH /wp-json/enterprise-auth/v1/scim/v2/Groups/{id}`

## Identity Governance

All controls in this section target **SSO-bound users** — any WordPress account that has been provisioned or linked via SAML, OIDC, or SCIM (identified by `_enterprise_auth_idp_uid` or `enterprise_iam_scim_id` usermeta). User ID 1 (break-glass admin) is always exempt.

### SSO-Only Account Lockdown

SSO-managed users cannot authenticate using a local password. The `authenticate` filter (priority 25, after WordPress password resolution) blocks any password-based login and returns an error directing the user to Single Sign-On. Password reset emails are also blocked via the `allow_password_reset` filter.

This prevents credential-stuffing attacks on accounts that are intended to be identity-provider-controlled and ensures that password authentication cannot be used to bypass multi-factor enforcement at the IdP.

### Email Change Protection

SSO-managed users cannot change their email address from the WordPress profile screen or REST API. Server-side validation rejects the change via `user_profile_update_errors`. The email field is also rendered `readonly` on the profile page with an inline note explaining that the address is managed by the organization's identity provider.

### Session Expiry Auto Re-Authentication

When a user authenticates via SSO, the plugin stores a per-site `enterprise_auth_last_idp` cookie (or `enterprise_auth_last_idp_{blog_id}` on Multisite) with a 90-day TTL, `HttpOnly`, `Secure`, `SameSite=Lax`, recording which IdP they used. When the SSO session expires:

- `force_sso_logout()` clears the WP session and redirects the user directly to the IdP's SSO login endpoint (SAML or OIDC) rather than dropping them on `wp-login.php`.
- The `login_init` hook additionally intercepts any `reauth=1` or `redirect_to`-bearing request to `wp-login.php` and redirects the user to their IdP automatically, skipping the login form entirely.

This produces a seamless zero-click re-authentication for users on still-active IdP sessions.

### Force Sign-In Mode

Each IdP can optionally require the user to re-authenticate at the IdP on every WordPress login attempt, bypassing any cached IdP session:

- **SAML**: sets `ForceAuthn="true"` in the `<AuthnRequest>`.
- **OIDC**: appends `prompt=login` to the authorization URL.

Enable with the **Force Re-Authentication** checkbox in each IdP's configuration form.

## Security Model

| Control | Detail |
|---|---|
| Break-glass admin isolation | User ID 1 and all `administrator` accounts are blocked from SSO login and SCIM modification |
| Immutable IdP UID binding | After first login, accounts are matched by `sub`/NameID, never by email alone |
| IdP spoofing prevention | Mismatched UID on an existing bound account blocks the login |
| Role ceiling | SSO and SCIM can never assign a role above the configured ceiling (default: `editor`) |
| Capability-aware privileged role gating | Roles exposing privileged capabilities are blocked for standard tenant IdPs even when a custom role name would otherwise pass a simple ceiling check |
| Local account protection | Local accounts on SSO-mapped domains are never redirected to the IdP |
| SSO-only account lockdown | Password login and password reset blocked for all SSO-managed users |
| Email change protection | SSO-managed users cannot change their email address |
| Session expiry auto re-auth | Expired sessions redirect to the user's IdP; the last-used IdP cookie is site-scoped on Multisite to prevent cross-site bleed |
| Force Sign-In Mode | Optional per-IdP ForceAuthn (SAML) / prompt=login (OIDC) to bypass cached IdP sessions |
| SCIM Bearer token auth | Bcrypt-hashed token verification on all SCIM endpoints |
| SCIM one-time token display | Plaintext token is shown only at generation time and is never stored |
| SCIM rate limiting | 300 requests/minute per window to prevent runaway syncs |
| SCIM suspension login block | Site-scoped suspensions and explicit network-scope deprovision block all login methods |
| SCIM deprovision fail-closed | Delete returns HTTP 409 when authored content cannot be reassigned safely |
| Multisite tenant isolation | Site-scoped usermeta, cookies, and transient keys prevent cross-site identity bleed on networks |
| OIDC state / nonce / verifier | Short-lived blog-scoped transients validated on every callback; no plugin-managed PHP session dependency |
| First-link clean sweep | Existing local accounts lose legacy passwords, application passwords, and active sessions when they first become IdP-managed |
| Identity audit events | `ea_identity_event` surfaces SSO login and SCIM lifecycle actions for downstream audit pipelines |
| SAML signature validation | Handled by the OneLogin SAML toolkit |
| WebAuthn challenges | Short-lived, server-side verified |

## Architecture

The codebase is structured in three layers, each separated by interface seams to keep pure logic testable in isolation and infrastructure swappable without touching domain code.

### Pure Logic Classes

| Class / Module | Extracted from | What it does |
|---|---|---|
| `SsoAccountPolicy` / `SsoAccountPolicyInterface` | `SecurityManager` | Pure SSO eligibility rules — no DB writes, no WordPress globals |
| `PasskeyEnrollmentValidator` | `WebAuthnHelper`, `PasskeyPolicy` | Pure passkey enrollment eligibility checks — role checks, network settings |
| `LoginStateMachine.js` | `passkey-login.js` | Pure login state transitions — no DOM, no fetch |
| `PasskeySectionViewModel.js` | `PasskeySection.jsx` | Pure props → display-state mapping — no React, no side effects |

### Interface / Adapter Seams

| Interface | Adapters | Consumers |
|---|---|---|
| `IdpRepositoryInterface` | `SiteIdpAdapter`, `NetworkIdpAdapter` | `IdpManager`, `NetworkIdpManager` |
| `SettingsSourceInterface` | `SiteSettingsSourceAdapter`, `NetworkSettingsSourceAdapter` | `EffectiveSettingsResolver`, `CurrentSiteIdpManager` |
| `UserIdentityRepositoryInterface` | `UserIdentityRepository` | `EnterpriseProvisioning`, `UserIdentityInspector` |
| `FederationHandlerInterface` | `SamlFederationAdapter`, `OidcFederationAdapter` | `FederationController` (dispatcher) |

### Shared Utilities

| Utility | Languages | Purpose |
|---|---|---|
| `WebAuthnEncoding` | PHP | Single authoritative base64 / base64url encode–decode for all WebAuthn flows |
| `webauthn-encoding.js` | JS | Mirrored ArrayBuffer ↔ base64 utilities consumed by `passkey-login.js` |

## Tech Stack

- PHP 8.3+
- WordPress REST API
- React (`@wordpress/components`, `@wordpress/element`)
- WebAuthn (`web-auth/webauthn-lib`)
- SAML (`onelogin/php-saml`)
- OIDC (`jumbojett/openid-connect-php`)

## License

GPL-2.0-or-later
