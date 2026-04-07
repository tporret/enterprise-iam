# Enterprise Auth - Identity and Access Management for WordPress

Enterprise Auth is a WordPress plugin for enterprise-ready authentication and identity workflows.

It combines:

- Passkeys (WebAuthn)
- SAML 2.0 Service Provider support
- OpenID Connect (OIDC) support
- Domain-based SSO routing
- Just-In-Time user provisioning
- Group-to-role mapping with wildcard fallback

## Highlights

- Identity-first login UX on `wp-login.php`
- Passwordless login with passkeys
- SAML metadata endpoint and ACS flow
- OIDC authorization and callback flow
- Unified provisioning engine for SAML and OIDC
- React admin UI for provider management

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

Example:

```text
Engineering -> editor
Admins -> administrator
* -> author
```

## Provisioning Behavior

On successful SSO authentication, the plugin:

1. Finds a user by email.
2. Creates the user if missing (JIT provisioning).
3. Applies mapped role (or wildcard fallback if configured).
4. Logs the user in and redirects.

## Main Endpoints

- `POST /wp-json/enterprise-auth/v1/route-login`
- `GET /wp-json/enterprise-auth/v1/saml/metadata`
- `GET /wp-json/enterprise-auth/v1/saml/login?idp_id={id}`
- `POST /wp-json/enterprise-auth/v1/saml/acs`
- `GET /wp-json/enterprise-auth/v1/oidc/login?idp_id={id}`
- `GET /wp-json/enterprise-auth/v1/oidc/callback`
- `GET|POST /wp-json/enterprise-auth/v1/passkeys/register`
- `GET|POST /wp-json/enterprise-auth/v1/passkeys/login`

## Tech Stack

- PHP 8.1+
- WordPress REST API
- React (`@wordpress/components`, `@wordpress/element`)
- WebAuthn (`web-auth/webauthn-lib`)
- SAML (`onelogin/php-saml`)
- OIDC (`jumbojett/openid-connect-php`)

## License

GPL-2.0-or-later
