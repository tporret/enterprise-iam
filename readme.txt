=== Enterprise Auth - Identity and Access Management ===
Contributors: enterprise-auth-team
Tags: iam, identity, access-management, saml, oidc, passkeys, webauthn, sso, security
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.0.0
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
* Security hardening controls for WordPress auth behavior
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

= What happens if a user does not exist in WordPress yet? =

The plugin can provision users automatically during successful SSO login (JIT provisioning).

= Is passkey login supported on wp-login.php? =

Yes. The plugin adds an identity-first login flow and passkey support on the native login page.

== Security Notes ==

* OIDC state is validated on callback and stored with short-lived transients.
* OIDC nonce validation is handled through the OIDC client flow.
* SAML assertions are validated by the SAML toolkit.
* WebAuthn challenges are short-lived and verified server-side.

== Changelog ==

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
