=== Enterprise Auth - Identity and Access Management ===
Contributors: enterprise-auth-team
Tags: iam, identity, access-management, saml, oidc, passkeys, webauthn, sso, security
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade Identity and Access Management for WordPress with passkeys, SAML 2.0, OIDC, and domain-based SSO routing.

== Description ==

Enterprise Auth provides a modern IAM layer for WordPress teams that need stronger authentication, centralized identity, and cleaner admin controls.

Key features:

* Passkey authentication (WebAuthn) for passwordless login
* Enterprise SSO with SAML 2.0 Service Provider flow
* Enterprise SSO with OpenID Connect (Authorization Code flow)
* Domain-based login routing (email domain -> provider)
* Just-In-Time user provisioning for SAML and OIDC
* Group-to-role mapping for both protocols
* Wildcard role mapping support using `*` (fallback role)
* Configurable JIT role ceiling — prevents SSO from granting more than a capped role
* Break-glass admin isolation — SSO never targets administrator accounts
* Strict account binding using immutable IdP UID (OIDC `sub` / SAML NameID)
* Correct local vs SSO routing — local accounts on SSO domains always reach the password form
* Security hardening controls for WordPress auth behaviour
* React-based admin configuration UI

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/enterprise-iam/`, or install it via your deployment workflow.
2. Activate the plugin through the WordPress Plugins screen.
3. Ensure dependencies are available:
   * Composer vendor directory (autoload)
   * Built frontend assets in `build/`
4. Open `WP Admin -> Enterprise Auth` and configure:
   * Passkeys
   * SAML providers
   * OIDC providers
   * Domain mappings
   * Role mappings

== Frequently Asked Questions ==

= Does this support both SAML and OIDC? =

Yes. The plugin supports both SAML 2.0 and OpenID Connect providers, and routes users dynamically based on email domain.

= How does role mapping work? =

You can map incoming IdP groups to WordPress roles. Mapping is case-insensitive for group names.

If your IdP does not send group claims, add a wildcard mapping with group name `*` to apply a default role.

The `administrator` role is intentionally excluded from the role mapping UI. Use the Role Ceiling setting (General tab) to control the maximum role SSO can assign — default is `editor`.

= What happens if a user does not exist in WordPress yet? =

The plugin can provision users automatically during successful SSO login (JIT provisioning). New users are created at `subscriber` level and then promoted by role mapping, subject to the Role Ceiling.

= Can an admin account be taken over via SSO? =

No. User ID 1 and any account with the `administrator` role are blocked from SSO login entirely. They must always log in with a local password or passkey. This ensures a break-glass account is always available even if the IdP is unavailable or compromised.

= What if my admin email domain is mapped to an SSO provider? =

The login router checks whether the specific account is a local account before routing to SSO. Local accounts (no SSO provider binding) always see the password/passkey form, regardless of their email domain.

= Is passkey login supported on wp-login.php? =

Yes. The plugin adds an identity-first login flow and passkey support on the native login page.

== Security Notes ==

* OIDC state is validated on callback and stored with short-lived transients.
* OIDC nonce validation is handled through the OIDC client flow.
* SAML assertions are validated by the SAML toolkit.
* WebAuthn challenges are short-lived and verified server-side.
* Break-glass admin isolation: user ID 1 and all administrator accounts are blocked from SSO login.
* Strict account binding: after first login, users are matched by immutable IdP UID (`sub` / NameID), not email. A mismatch blocks the login.
* Role ceiling: SSO provisioning can never assign a role above the configured ceiling, regardless of IdP payload.
* Local account protection: local accounts on SSO-mapped domains are never redirected to an IdP.

== Changelog ==

= 1.1.0 =
* Security: Break-glass admin isolation — SSO login blocked for user ID 1 and all administrator accounts
* Security: Strict account binding — IdP immutable UID (OIDC `sub` / SAML NameID) stored on first login and enforced on all subsequent logins; mismatched UID blocks the login
* Security: JIT role ceiling — new General setting caps the maximum role SSO provisioning can assign (default: `editor`); `administrator` removed from role mapping UI
* Fix: Login router now returns `local` for accounts with no SSO provider binding, even when the email domain is mapped to an IdP — ensures break-glass and other local accounts always reach the password/passkey form
* Fix: Password field was hidden and disabled after routing to local login — now correctly shown and enabled
* Fix: Login layout for local accounts now shows password → Log In → divider → Passkey button in the correct order

= 1.0.1 =
* Added PHPCS/WPCS static analysis tooling (`composer lint`, `composer lint:fix`)
* Hardened OIDC callback: provider `error` parameter is now surfaced as a user-readable redirect message
* Fixed SAML admin tab incorrectly listing OIDC identity providers

= 1.0.0 =
* Initial public release
* Passkey registration and login (WebAuthn)
* SAML 2.0 SP flow (metadata, login, ACS)
* OIDC login and callback flow
* Unified JIT provisioning service
* Domain-based login router
* Group and wildcard role mapping

== Upgrade Notice ==

= 1.0.0 =
Initial release of Enterprise Auth with passkeys, SAML, and OIDC support.
