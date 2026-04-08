# Enterprise Auth - Identity and Access Management for WordPress

Enterprise Auth is a WordPress plugin for enterprise-ready authentication and identity workflows.

It combines:

- Passkeys (WebAuthn)
- SAML 2.0 Service Provider support
- OpenID Connect (OIDC) support
- Domain-based SSO routing
- Just-In-Time user provisioning
- Group-to-role mapping with wildcard fallback
- Break-glass admin isolation
- Immutable IdP UID account binding
- Configurable JIT role ceiling
- SCIM 2.0 user provisioning and deprovisioning
- SCIM group-to-role entitlement mapping

## Highlights

- Identity-first login UX on `wp-login.php` with correct local vs SSO routing
- Passwordless login with passkeys
- SAML metadata endpoint and ACS flow
- OIDC authorization and callback flow
- Unified provisioning engine for SAML and OIDC
- SCIM 2.0 endpoint with Bearer token auth and rate limiting
- React admin UI for provider management
- Break-glass admin isolation — SSO cannot target administrator accounts
- Strict account binding via immutable IdP UID (OIDC `sub` / SAML NameID)
- Configurable JIT role ceiling to prevent privilege escalation

## Requirements

- WordPress 6.0+
- PHP 8.1+
- Composer dependencies installed (`vendor/`)
- Frontend assets built (`build/`)

## Installation

### Production-style install

1. Place the plugin in `wp-content/plugins/enterprise-iam`.
2. Ensure `vendor/` and `build/` are present.
3. Activate the plugin from WordPress admin.
4. Configure providers in `WP Admin -> Enterprise Auth`.

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

Configure passkey registration and login for users through the plugin settings and login page flow.

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

## Provisioning Behaviour

On successful SSO authentication, the plugin applies the following steps in order:

1. **Break-glass check** — rejects SSO login for user ID 1 and any `administrator` account. These accounts must always log in locally (password or passkey).
2. **Primary user lookup** — searches for an existing user by the IdP's immutable unique identifier stored in `_enterprise_auth_idp_uid` usermeta. This is the OIDC `sub` claim or the SAML `NameID`.
3. **First-time binding** — if no UID match is found, falls back to email lookup. On a successful email match the IdP UID is stored for all future logins. If the stored UID does not match the incoming UID, the login is blocked (IdP spoofing prevention).
4. **JIT creation** — if no matching user exists, creates a new WordPress account at `subscriber` level and stores both the IdP provider ID and UID.
5. **Role mapping** — applies group-to-role mapping, capped at the configured Role Ceiling.
6. **Login** — sets the auth cookie and fires `wp_login`.

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
- Copy the plaintext token exactly once (never retrievable later)

Token generation uses `POST /wp-json/enterprise-auth/v1/settings/scim-token` and stores only a bcrypt hash server-side.

### Rate Limiting

SCIM endpoints enforce a 300 requests/minute rate limit using WordPress transients. Exceeding the limit returns HTTP 429.

### User Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/scim/v2/Users` | List users as a SCIM ListResponse. Supports `startIndex`, `count`, and basic `filter` (`userName eq "..."`) for connector validation/reconciliation. |
| `POST` | `/scim/v2/Users` | Create a new user. Maps `userName` → email, `externalId` → immutable SCIM binding, `name` → first/last name. Returns 201 or 409 on conflict. |
| `GET` | `/scim/v2/Users/{id}` | Fetch a single user by SCIM/WP user ID. Returns 404 when missing. |
| `PUT` | `/scim/v2/Users/{id}` | Full replace of a user's attributes. |
| `PATCH` | `/scim/v2/Users/{id}` | Partial update. Supports `active: false` to suspend (remove roles, set `is_scim_suspended` meta) and `active: true` to reactivate. Handles both standard and Azure AD PatchOp formats. |

Administrator accounts (user ID 1 and `administrator` role) are protected from SCIM modifications (HTTP 403).

### Group Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/scim/v2/Groups` | List groups as a SCIM ListResponse (WordPress roles are exposed as SCIM Groups). |
| `POST` | `/scim/v2/Groups` | Create a group. The `displayName` is matched against the existing role mapping engine and applied to all `members`. |
| `PATCH` | `/scim/v2/Groups/{id}` | Update group membership. Supports `add`/`replace` operations on the `members` path. |

Group role assignment uses the same mapping engine as SAML/OIDC (exact match → `*` wildcard fallback), respecting the configured Role Ceiling.

### Suspension & Login Block

When an IdP sends `PATCH` with `active: false`, the user's roles are removed and an `is_scim_suspended` meta flag is set. Suspended users are blocked from all login methods (password, passkey, SSO) with the message "Account suspended by Identity Provider."

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
- `GET|PUT|PATCH /wp-json/enterprise-auth/v1/scim/v2/Users/{id}`
- `GET|POST /wp-json/enterprise-auth/v1/scim/v2/Groups`
- `PATCH /wp-json/enterprise-auth/v1/scim/v2/Groups/{id}`

## Security Model

| Control | Detail |
|---|---|
| Break-glass admin isolation | User ID 1 and all `administrator` accounts are blocked from SSO login and SCIM modification |
| Immutable IdP UID binding | After first login, accounts are matched by `sub`/NameID, never by email alone |
| IdP spoofing prevention | Mismatched UID on an existing bound account blocks the login |
| Role ceiling | SSO and SCIM can never assign a role above the configured ceiling (default: `editor`) |
| Local account protection | Local accounts on SSO-mapped domains are never redirected to the IdP |
| SCIM Bearer token auth | Bcrypt-hashed token verification on all SCIM endpoints |
| SCIM one-time token display | Plaintext token is shown only at generation time and is never stored |
| SCIM rate limiting | 300 requests/minute per window to prevent runaway syncs |
| SCIM suspension login block | Deprovisioned users are blocked from all login methods |
| OIDC state / nonce | Short-lived transients validated on every callback |
| SAML signature validation | Handled by the OneLogin SAML toolkit |
| WebAuthn challenges | Short-lived, server-side verified |

## Tech Stack

- PHP 8.1+
- WordPress REST API
- React (`@wordpress/components`, `@wordpress/element`)
- WebAuthn (`web-auth/webauthn-lib`)
- SAML (`onelogin/php-saml`)
- OIDC (`jumbojett/openid-connect-php`)

## License

GPL-2.0-or-later
