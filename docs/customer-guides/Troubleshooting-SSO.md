# SSO Troubleshooting Reference

This reference maps masked login errors and internal federation diagnostics to likely IdP configuration issues.

## What users see vs what admins should check

User-facing redirect is intentionally masked:

- `?sso_error=federation_failed`

If available, a correlation value is appended:

- `&sso_error_ref=<uuid>`

Use `sso_error_ref` to locate the matching server log event from Enterprise IAM federation logging.

## Log prefixes

- SAML diagnostics: `[DEBUG-fed-saml]`
- OIDC diagnostics: `[DEBUG-fed-oidc]`

All detailed failures are logged server-side with protocol/source context and correlation reference.

## SAML diagnostics map

## `[DEBUG-fed-saml] [saml_missing_response]`

Meaning:
- ACS endpoint did not receive `SAMLResponse`.

Likely IdP/config issue:
- Wrong binding or app posted to wrong URL.
- Reply URL mismatch, or middleware stripped POST body.

Fix:
- Ensure Reply URL is `https://[tenant].yoursaas.com/wp-json/enterprise-auth/v1/saml/acs`.
- Ensure HTTP-POST binding is used for assertion delivery.

## `[DEBUG-fed-saml] [saml_flow_validation_failed]`

Meaning:
- RelayState/request correlation failed or expired.

Likely IdP/config issue:
- Stale browser tab, replayed assertion, or delayed response beyond flow TTL.

Fix:
- Retry login from a fresh browser session.
- Verify proxies/WAF are not modifying RelayState.

## `[DEBUG-fed-saml] [saml_browser_binding_mismatch]`

Meaning:
- Browser-bound flow validation failed (request initiated in a different browser/session context).

Likely IdP/config issue:
- Cross-browser completion, strict cookie partitioning, or security middleware interference.

Fix:
- Complete the full SSO flow in one browser context.
- Check SameSite/cookie handling and reverse proxy behavior.

## `[DEBUG-fed-saml] [saml_idp_resolution_failed]`

Meaning:
- Could not resolve a valid SAML IdP config or request binding info.

Likely IdP/config issue:
- Wrong IdP selected, disabled IdP, missing entity/cert/SSO URL in app config.

Fix:
- Confirm active SAML IdP is enabled and selected.
- Validate IdP Entity ID, SSO URL, and certificate fields.

## `[DEBUG-fed-saml] [saml_assertion_invalid_signature]`

Meaning:
- Signature validation failed.

Likely IdP/config issue:
- Incorrect signing certificate in Enterprise IAM.
- Certificate rotated in IdP but not updated in app.
- Signature algorithm/signing setup mismatch.

Fix:
- Re-copy current IdP signing cert into `certificate`.
- Ensure signing policy aligns with required signed assertion/response.

## `[DEBUG-fed-saml] [saml_assertion_invalid_response]`

Meaning:
- SAML response failed structural/semantic validation.

Likely IdP/config issue:
- Audience, destination, or InResponseTo mismatch.
- Response generated for different SP entity ID.

Fix:
- Verify Entity ID and ACS URL values exactly match Enterprise IAM tenant values.
- Ensure request/response correlation is enabled and intact.

## `[DEBUG-fed-saml] [saml_assertion_validation_failed]`

Meaning:
- General assertion validation failure not classified as signature/invalid_response.

Likely IdP/config issue:
- Mixed claim format, clock skew, malformed assertion.

Fix:
- Validate IdP SAML response with an XML/SAML validator.
- Check server and IdP time synchronization.

## `[DEBUG-fed-saml] [saml_not_authenticated]`

Meaning:
- Assertion processed but authentication status is false.

Likely IdP/config issue:
- IdP policy denied auth or produced non-authenticated response.

Fix:
- Review IdP authentication/sign-in policy and user assignment.

## `[DEBUG-fed-saml] [saml_provisioning_failed]`

Meaning:
- Identity accepted but account provisioning/binding failed.

Likely IdP/config issue:
- Missing valid email/UID mapping, issuer mismatch, or account-binding policy conflict.

Fix:
- Verify email and persistent ID claims are present and stable.
- Verify issuer and user binding are consistent.

## `[DEBUG-fed-saml] [saml_acs_exception]`

Meaning:
- Unhandled exception during ACS pipeline.

Likely IdP/config issue:
- Usually secondary to malformed payload or endpoint mismatch.

Fix:
- Inspect full log entry by `sso_error_ref` and validate IdP metadata values.

## OIDC diagnostics map

## `[DEBUG-fed-oidc] [oidc_provider_error]`

Meaning:
- IdP returned OIDC error in callback (`error` / `error_description`).

Likely IdP/config issue:
- User denied consent, app assignment missing, or policy blocked request.

Fix:
- Review Okta/IdP sign-on policy and app assignment.
- Validate requested scopes and consent settings.

## `[DEBUG-fed-oidc] [oidc_missing_code_or_state]`

Meaning:
- Callback missing `code` or `state`.

Likely IdP/config issue:
- Redirect URI mismatch, callback rewrite, or query parameters stripped.

Fix:
- Whitelist exact redirect URI:
  `https://[tenant].yoursaas.com/wp-json/enterprise-auth/v1/oidc/callback`
- Check reverse proxy/WAF query-string handling.

## `[DEBUG-fed-oidc] [oidc_state_mismatch]`

Meaning:
- Returned `state` does not match stored flow state.

Likely IdP/config issue:
- Wrong callback request, stale login, or state tampering/rewrites.

Fix:
- Restart login from scratch.
- Ensure state parameter is preserved end-to-end.

## `[DEBUG-fed-oidc] [oidc_state_validation_failed]`

Meaning:
- State flow could not be consumed (expired/invalid).

Likely IdP/config issue:
- Delayed callback, replayed callback, browser/session mismatch.

Fix:
- Retry immediately in one browser session.
- Check session storage and proxy caching behavior.

## `[DEBUG-fed-oidc] [oidc_provider_error_state_validation_failed]`

Meaning:
- IdP callback had provider error and state validation also failed.

Likely IdP/config issue:
- Combined provider-side denial and local state expiry/mismatch.

Fix:
- Resolve provider error first, then retest with fresh login flow.

## `[DEBUG-fed-oidc] [oidc_idp_or_pkce_resolution_failed]`

Meaning:
- IdP config missing/invalid, or PKCE nonce/verifier state unavailable.

Likely IdP/config issue:
- Disabled/wrong OIDC IdP.
- Incomplete flow storage or callback from wrong initiation.

Fix:
- Confirm correct enabled IdP.
- Ensure callback originates from current login initiation.

## `[DEBUG-fed-oidc] [oidc_runtime_validation_failed]`

Meaning:
- Runtime endpoint validation failed before token exchange.

Likely IdP/config issue:
- Endpoint URLs are non-HTTPS, invalid, localhost, or private/internal hosts.

Fix:
- Use valid public HTTPS endpoints for issuer/auth/token/userinfo/jwks.

## `[DEBUG-fed-oidc] [oidc_token_exchange_failed]`

Meaning:
- Token exchange or token validation failed.

Likely IdP/config issue:
- Invalid client credentials.
- Wrong token endpoint.
- PKCE verifier mismatch.
- Nonce validation failure.
- JWKS/signature or issuer/audience mismatch.

Fix:
- Recheck client ID/secret.
- Verify issuer, token endpoint, jwks_uri.
- Ensure PKCE and nonce are not altered by intermediaries.

## `[DEBUG-fed-oidc] [oidc_missing_valid_email]`

Meaning:
- No valid email claim found after ID token/userinfo evaluation.

Likely IdP/config issue:
- Email scope/claim not configured or claim mapping mismatch.

Fix:
- Ensure `email` claim is released and valid.
- If custom mapping is enabled, ensure mapped claim key exists.

## `[DEBUG-fed-oidc] [oidc_issuer_mismatch]`

Meaning:
- Token `iss` does not match configured issuer.

Likely IdP/config issue:
- Wrong issuer URL in app configuration or wrong authorization server.

Fix:
- Set issuer exactly to the authorization server issuing the token.

## `[DEBUG-fed-oidc] [oidc_provisioning_failed]`

Meaning:
- OIDC identity validated but user provisioning/binding failed.

Likely IdP/config issue:
- Missing immutable user ID (`sub`) continuity, email verification policy, or account binding conflict.

Fix:
- Ensure stable `sub`, valid `email`, and expected `email_verified` behavior.

## `[DEBUG-fed-oidc] [oidc_callback_exception]`

Meaning:
- Unhandled exception in callback pipeline.

Likely IdP/config issue:
- Usually secondary to malformed callback payload or endpoint data.

Fix:
- Use `sso_error_ref` to inspect full log details and verify endpoint configuration.

## Fast triage workflow for IT admins

1. Reproduce once and capture full callback URL.
2. Record `sso_error` and `sso_error_ref`.
3. Find matching server log entry by reference.
4. Use the signal mapping above to isolate the exact IdP field/policy mismatch.
5. Retest with a fresh browser session after updating IdP settings.
