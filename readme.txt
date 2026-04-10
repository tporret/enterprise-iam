=== Enterprise Auth - Identity and Access Management ===
Contributors: enterprise-auth-team
Tags: iam, identity, access-management, saml, oidc, passkeys, webauthn, sso, security
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.5.1
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
* Multisite-aware tenant isolation for identity metadata, re-auth cookies, and protocol transient state
* Group-to-role mapping for both protocols
* Wildcard role mapping support using `*` (fallback role)
* Configurable JIT role ceiling — prevents SSO from granting more than a capped role
* Break-glass admin isolation — SSO never targets administrator accounts
* Strict account binding using immutable IdP UID (OIDC `sub` / SAML NameID)
* SCIM 2.0 user provisioning and deprovisioning with Bearer token auth
* SCIM DELETE semantics with safe reassignment, explicit site steward support, and fail-closed 409 responses when content cannot be reassigned safely
* Multisite network deprovision with `DELETE /Users/{id}?scope=network` and a network-wide suspension flag
* SCIM 2.0 read operations (`GET /Users`, `GET /Users/{id}`, `GET /Groups`) for Okta/Azure AD/MidPoint connector validation
* SCIM group-to-role entitlement mapping using the existing role mapping engine
* SCIM suspension blocks all login methods (password, passkey, SSO)
* SCIM Provisioning admin tab to view SCIM Base URL, generate one-time tokens, and configure a site-level Deprovision Steward
* Existing network users can be attached to the current site during Multisite SCIM create instead of duplicated globally
* Custom attribute mapping per IdP — override the default claim keys for email, first name, and last name with an admin UI toggle and one-click presets for Azure AD (SAML + OIDC), Shibboleth/InCommon OIDs, and Standard/Okta
* SSO-only account lockdown — password login and password reset disabled for all SSO-managed users
* Email change protection — SSO-managed users cannot change their email address
* Session expiry auto re-authentication — expired sessions redirect transparently back to the user's IdP
* Force Sign-In Mode — per-IdP toggle to bypass cached IdP sessions (SAML ForceAuthn / OIDC prompt=login)
* Capability-aware role hardening blocks custom elevated roles for standard tenant IdPs
* First-link clean sweep revokes legacy local credentials when an account becomes IdP-managed
* Identity audit hooks (`ea_identity_event`) for SSO login and SCIM lifecycle actions
* REST API cache-control hardening — all plugin endpoints return `Cache-Control: no-store` to prevent CDN/proxy caching of sensitive dynamic responses
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
   * SCIM Provisioning (Base URL + token generation + Deprovision Steward)
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

= How does SCIM deprovisioning work on Multisite? =

`DELETE /Users/{id}` removes the user from the current site and clears that site's identity bindings. `DELETE /Users/{id}?scope=network` preflights every site membership, applies per-site reassignment policy, and then removes the user from every site if the full plan is safe.

= Can I control who receives content during deprovisioning? =

Yes. Each site can configure a Deprovision Steward in the SCIM settings screen. If no steward is configured, the plugin falls back deterministically to an eligible local administrator. If authored content exists and no valid target can be resolved, delete is rejected with HTTP 409.

== Security Notes ==

* Multisite isolation: SSO / SCIM binding metadata, re-auth cookies, and protocol transients are site-scoped to prevent cross-site bleed on shared networks.
* OIDC state, nonce, and code verifier are validated on callback and stored with short-lived transients rather than plugin-managed PHP sessions.
* OIDC nonce validation is handled through the OIDC client flow.
* SAML assertions are validated by the SAML toolkit.
* WebAuthn challenges are short-lived and verified server-side.
* Break-glass admin isolation: user ID 1 and all administrator accounts are blocked from SSO login and SCIM modification.
* Strict account binding: after first login, users are matched by immutable IdP UID (`sub` / NameID), not email. A mismatch blocks the login.
* First-link clean sweep: when an existing local account becomes IdP-managed, the plugin revokes the local password, application passwords, and active sessions before finalizing the binding.
* Role ceiling: SSO and SCIM provisioning can never assign a role above the configured ceiling, regardless of IdP payload.
* Capability-aware role hardening: privileged roles are blocked for standard tenant IdPs even when custom role names would bypass a simple textual allowlist.
* SCIM Bearer token authentication: bcrypt-hashed token verification on all SCIM endpoints.
* SCIM one-time token disclosure: plaintext tokens are shown once at generation and never stored server-side.
* SCIM rate limiting: 300 requests/minute to prevent runaway IdP syncs.
* SCIM suspension login block: site-scoped suspensions and explicit network-scope deprovision block all login methods.
* SCIM delete fail-closed policy: if authored content cannot be safely reassigned to a valid steward, delete is rejected with HTTP 409 rather than proceeding partially.
* SCIM network deprovision: `DELETE /Users/{id}?scope=network` evaluates all site memberships first and sets a network-wide suspension flag after successful removal.
* Local account protection: local accounts on SSO-mapped domains are never redirected to an IdP.
* SSO-only account lockdown: password login and password reset are blocked for all SSO-managed users (identified by `_enterprise_auth_idp_uid` or `enterprise_iam_scim_id` meta). User ID 1 is exempt.
* Email change protection: SSO-managed users cannot change their email address via the profile screen or REST API.
* Session expiry auto re-auth: the `enterprise_auth_last_idp` cookie (site-scoped on Multisite; 90-day, HttpOnly, Secure, SameSite=Lax) enables seamless redirect to the correct IdP when a WP session expires.
* Force Sign-In Mode: optional per-IdP setting appends ForceAuthn=true (SAML) or prompt=login (OIDC) to each authentication request.
* REST API cache-control: all `enterprise-auth/` REST endpoints return `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, and `Expires: 0` headers. This defends against web cache deception and poisoning attacks where CDN or proxy URL-parser discrepancies could cause sensitive dynamic responses to be stored and served to other users.
* Auditability: `ea_identity_event` hooks fire on successful SSO login and on SCIM lifecycle events, with delete events carrying reassignment and request metadata where available.

== Changelog ==

= 1.5.1 =
* Security: Multisite tenant isolation — site-scoped identity metadata, re-auth cookies, and protocol transient keys prevent cross-site bleed on shared networks
* Security: OIDC callback hardening — state, nonce, and PKCE verifier now use short-lived transients instead of plugin-managed PHP sessions
* Security: first-link clean sweep — existing local accounts lose legacy passwords, application passwords, and active sessions when they first become IdP-managed
* Security: capability-aware role hardening — privileged roles are blocked for standard tenant IdPs even when custom role names would otherwise bypass a simple ceiling check
* Security: REST API cache-control hardening — all `enterprise-auth/` REST responses now include `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, and `Expires: 0`
* Feature: SCIM create on Multisite can attach an existing network user to the current site instead of creating a duplicate global account
* Feature: SCIM delete semantics — `DELETE /Users/{id}` now performs safe single-site and Multisite deprovisioning with explicit reassignment planning and HTTP 409 fail-closed behavior when content cannot be safely reassigned
* Feature: Multisite network deprovision — `DELETE /Users/{id}?scope=network` preflights every site membership, applies per-site reassignment, removes memberships, and then blocks future login via a network-wide suspension flag
* Feature: SCIM admin UI now includes a per-site Deprovision Steward selector for deterministic content reassignment during automated offboarding
* Feature: identity audit hooks — `ea_identity_event` is emitted for successful SSO logins and SCIM lifecycle actions

= 1.5.0 =
* Security: SSO-only account lockdown — password login blocked for SSO-managed users via `authenticate` filter (priority 25); password reset blocked via `allow_password_reset` filter
* Security: Email change protection — `user_profile_update_errors` rejects email changes for SSO-managed users; profile page renders email field as readonly with an IdP-managed note
* Feature: Session expiry auto re-auth — `enterprise_auth_last_idp` cookie stored on every SSO login; `login_init` hook redirects expired sessions directly to the user's IdP; `force_sso_logout()` redirects to IdP re-auth URL instead of wp-login.php
* Feature: Force Sign-In Mode — per-IdP `force_reauth` toggle; SAML AuthnRequests include ForceAuthn=true; OIDC authorization requests include prompt=login
* Feature: Force Re-Authentication checkbox added to SAML and OIDC IdP configuration forms in the React admin UI

= 1.4.0 =
* Feature: Custom attribute mapping — added "Override Default Attribute Mapping" toggle to SAML and OIDC IdP configuration forms
* Feature: Per-IdP attribute key inputs for Email, First Name, and Last Name claim/attribute names
* Feature: Load Preset dropdown auto-fills all three keys for Standard/Okta, Azure AD (Microsoft Entra), and Shibboleth/InCommon (OIDs) on SAML; Standard OIDC and Azure AD OIDC on OIDC
* Feature: Custom keys are persisted in `wp_options` (`enterprise_auth_idps`) alongside all other IdP config and fully sanitized server-side
* Feature: SAML ACS controller uses custom attribute keys when override is enabled, falling back to the full OID/claim URI chain when disabled
* Feature: OIDC callback controller uses custom claim keys (including the UserInfo fallback path) when override is enabled

= 1.3.0 =
* Feature: SCIM read operations — GET /scim/v2/Users returns RFC 7644 ListResponse with pagination (`startIndex`, `count`) and basic `userName eq "..."` filtering
* Feature: SCIM read operations — GET /scim/v2/Users/{id} returns a single SCIM User resource with 404 handling
* Feature: SCIM read operations — GET /scim/v2/Groups returns RFC 7644 ListResponse for available groups (WordPress roles)
* Feature: SCIM admin UI — new SCIM Provisioning tab shows absolute SCIM Base URL for IdP configuration
* Feature: SCIM admin UI — Generate New SCIM Token action via POST /enterprise-auth/v1/settings/scim-token
* Security: SCIM token plaintext is returned strictly once; only bcrypt hash is stored in wp_options (`enterprise_iam_scim_token`)

= 1.2.0 =
* Feature: SCIM 2.0 user provisioning — POST /scim/v2/Users creates WordPress accounts with externalId binding and conflict detection (409)
* Feature: SCIM 2.0 user update — PUT /scim/v2/Users/{id} replaces user attributes with admin protection (403)
* Feature: SCIM 2.0 deprovisioning — PATCH /scim/v2/Users/{id} with `active: false` suspends the user (removes roles, sets `is_scim_suspended` meta); supports both standard and Azure AD PatchOp formats
* Feature: SCIM 2.0 group entitlement mapping — POST and PATCH /scim/v2/Groups assigns roles to members via the existing role mapping engine with role ceiling enforcement
* Feature: SCIM Bearer token authentication — bcrypt-hashed token stored in wp_options, verified on every SCIM request
* Feature: SCIM rate limiting — 300 requests/minute sliding window using WordPress transients (HTTP 429 on exceeded)
* Security: Suspended users are blocked from all login methods (password, passkey, SSO) with "Account suspended by Identity Provider" error
* Security: Administrator accounts (user ID 1 and administrator role) are protected from all SCIM modifications

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

= 1.5.1 =
Security and Multisite hardening release. Review the SCIM Deprovision Steward setting on each site before enabling automated delete flows, especially on Multisite. No database schema changes.

= 1.5.0 =
Adds identity governance controls: SSO-only account lockdown, email change protection, session expiry auto re-auth, and Force Sign-In Mode. No database changes. Existing IdP configurations are unaffected; the new `force_reauth` field defaults to false.

= 1.4.0 =
Adds custom attribute mapping per IdP. No breaking changes.

= 1.0.0 =
Initial release of Enterprise Auth with passkeys, SAML, and OIDC support.
